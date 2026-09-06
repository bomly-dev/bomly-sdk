package sdk

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk/purlkit"
)

// TestPackageURLTypeForValuesMatchesLegacySwitch pins that the purlkit table
// answers exactly like the historical root switch for every token either of
// them knows, so the S3 delegation is behavior-preserving by construction.
// legacyPackageURLTypeSwitch is the frozen pre-delegation implementation; it
// exists only for this parity check.
func TestPackageURLTypeForValuesMatchesLegacySwitch(t *testing.T) {
	// Deliberate corrections over the legacy switch: manager-only
	// coordinates (pnpm and yarn graphs carry no ecosystem token) used to
	// fall through to the verbatim fallback and mint non-spec purl types
	// such as pkg:pnpm. Each delta is a chosen row, not an accident.
	chosenDeltas := map[string]string{
		"pnpm": "npm", "yarn": "npm", "bun": "npm",
		"gradle": "maven",
		"pdm":    "pypi", "setuppy": "pypi", "setup.py": "pypi",
		"gemspec": "gem",
	}
	tokens := []string{
		"", "nuget", "dotnet", "cargo", "rust", "pub", "dart", "cocoapods",
		"swift", "swiftpm", "github-actions", "githubactions", "conan", "cpp",
		"mix", "hex", "elixir", "rebar", "otp", "erlang", "haskell", "cabal",
		"stack", "hackage", "r", "r-package", "cran", "ocaml", "opam", "dpkg",
		"deb", "sbt", "scala", "ruby", "gem", "rubygems", "bundler", "php",
		"composer", "python", "pypi", "pip", "pipenv", "poetry", "uv", "go",
		"gomod", "golang", "npm", "pnpm", "yarn", "bun", "maven", "gradle",
		"apk", "rpm", "alpm", "conda", "generic", "unknown-token",
	}
	for _, first := range tokens {
		for _, second := range tokens {
			got := PackageURLTypeForValues(first, second)
			want := legacyPackageURLTypeSwitch(first, second)
			_, firstDelta := chosenDeltas[first]
			_, secondDelta := chosenDeltas[second]
			if firstDelta || secondDelta {
				continue // asserted separately below
			}
			if got != want {
				t.Errorf("PackageURLTypeForValues(%q, %q) = %q, legacy = %q", first, second, got, want)
			}
		}
	}
	for token, want := range chosenDeltas {
		if got := PackageURLTypeForValues(token); got != want {
			t.Errorf("PackageURLTypeForValues(%q) = %q, want chosen delta %q", token, got, want)
		}
	}
}

// TestBuildPackageURLKeepsLegacyHygiene pins the root wrapper's input
// hygiene (backslash folding, slash trimming, fallback rendering) across the
// purlkit delegation.
func TestBuildPackageURLKeepsLegacyHygiene(t *testing.T) {
	cases := []struct {
		name string
		typ, namespace, pkgName, version,
		want string
	}{
		{"backslashes fold", "golang", `github.com\google`, "uuid", "v1.0.0", "pkg:golang/github.com/google/uuid@v1.0.0"},
		{"slashes trim", "npm", "/scope/", "/name/", "1.0.0", "pkg:npm/%40scope/name@1.0.0"},
		{"empty type", "", "ns", "name", "1", ""},
		{"empty name", "npm", "ns", "", "1", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := BuildPackageURL(tc.typ, tc.namespace, tc.pkgName, tc.version); got != tc.want {
				t.Fatalf("BuildPackageURL = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestCanonicalEcosystemCoversTheFullVocabulary walks the SDK's complete
// package-manager vocabulary and fails when purlkit's table cannot resolve a
// manager the SDK declares — the drift guard Codex asked for: a new manager
// or ecosystem cannot be forgotten in the kit silently. "multiple" is the
// one documented refusal (it names a set of managers, not an ecosystem).
func TestCanonicalEcosystemCoversTheFullVocabulary(t *testing.T) {
	refused := map[string]string{
		PackageManagerMultiple.Name(): "names a set of managers, not an ecosystem",
	}
	for _, manager := range AllPackageManagers() {
		name := manager.Name()
		if _, isRefused := refused[name]; isRefused {
			if _, ok := purlkit.CanonicalEcosystem(name); ok {
				t.Errorf("manager %q resolved but is documented as refused", name)
			}
			continue
		}
		canonical, ok := purlkit.CanonicalEcosystem(name)
		if !ok {
			t.Errorf("manager %q is not recognized by purlkit.CanonicalEcosystem", name)
			continue
		}
		if ecosystem := manager.Ecosystem(); ecosystem != EcosystemUnknown && canonical != string(ecosystem) {
			t.Errorf("manager %q → %q, but the SDK says its ecosystem is %q", name, canonical, ecosystem)
		}
	}
	for _, ecosystem := range []Ecosystem{
		EcosystemNPM, EcosystemMaven, EcosystemGo, EcosystemPython, EcosystemALPM,
		EcosystemAPK, EcosystemCPP, EcosystemConda, EcosystemDart, EcosystemDPKG,
		EcosystemElixir, EcosystemErlang, EcosystemGitHub, EcosystemHaskell,
		EcosystemHomebrew, EcosystemLua, EcosystemDotNet, EcosystemNix,
		EcosystemOCaml, EcosystemPHP, EcosystemPortage, EcosystemProlog,
		EcosystemR, EcosystemRPM, EcosystemRuby, EcosystemRust, EcosystemScala,
		EcosystemSBOM, EcosystemSnap, EcosystemSwift, EcosystemTerraform,
		EcosystemWordPress, EcosystemOther,
	} {
		canonical, ok := purlkit.CanonicalEcosystem(string(ecosystem))
		if !ok || canonical != string(ecosystem) {
			t.Errorf("ecosystem %q does not resolve to itself: (%q, %v)", ecosystem, canonical, ok)
		}
	}
}

// TestEcosystemForPURLTypeAnswersEveryRowTheCLICopiesLost pins the join the
// root package now owns. The five rows at the top are the ones bomly-cli's
// benchmark copy never learned, so they came back unknown there; the rest are
// the types whose spec name differs from the Bomly token, plus the direct
// ones the type table deliberately omits and only the alias table answers.
func TestEcosystemForPURLTypeAnswersEveryRowTheCLICopiesLost(t *testing.T) {
	rows := map[string]Ecosystem{
		"hackage": EcosystemHaskell,
		"cran":    EcosystemR,
		"opam":    EcosystemOCaml,
		"deb":     EcosystemDPKG,
		"otp":     EcosystemErlang,

		"golang":        EcosystemGo,
		"cargo":         EcosystemRust,
		"nuget":         EcosystemDotNet,
		"pypi":          EcosystemPython,
		"gem":           EcosystemRuby,
		"composer":      EcosystemPHP,
		"pub":           EcosystemDart,
		"conan":         EcosystemCPP,
		"cocoapods":     EcosystemSwift,
		"swift":         EcosystemSwift,
		"maven":         EcosystemMaven,
		"githubactions": EcosystemGitHub,

		"npm":       EcosystemNPM,
		"apk":       EcosystemAPK,
		"rpm":       EcosystemRPM,
		"alpm":      EcosystemALPM,
		"conda":     EcosystemConda,
		"nix":       EcosystemNix,
		"homebrew":  EcosystemHomebrew,
		"portage":   EcosystemPortage,
		"snap":      EcosystemSnap,
		"terraform": EcosystemTerraform,
		"wordpress": EcosystemWordPress,
		"lua":       EcosystemLua,
	}
	for purlType, want := range rows {
		if got := EcosystemForPURLType(purlType); got != want {
			t.Errorf("EcosystemForPURLType(%q) = %q, want %q", purlType, got, want)
		}
		// A resolved value must be a token the SDK vocabulary actually
		// knows, or the ecosystem it seeds a node with would fail the very
		// parse that gates a caller-supplied one.
		if _, err := ParseEcosystem(string(want)); err != nil {
			t.Errorf("EcosystemForPURLType(%q) answers %q, which ParseEcosystem rejects: %v", purlType, want, err)
		}
		// Untrusted spelling is folded, as it is everywhere else a purl type
		// is read: a SBOM stating "GOLANG " is the same type.
		if got := EcosystemForPURLType("  " + strings.ToUpper(purlType) + "\t"); got != want {
			t.Errorf("EcosystemForPURLType(padded, upper %q) = %q, want %q", purlType, got, want)
		}
	}
}

// TestEcosystemForPURLTypeRefusesWhatItCannotDecide pins the refusals as
// decisions rather than omissions. pkg:hex is the one the drifted CLI copy
// got wrong: it serves Elixir and Erlang alike, and answering either
// relabels half the packages that round-trip through it.
func TestEcosystemForPURLTypeRefusesWhatItCannotDecide(t *testing.T) {
	for _, purlType := range []string{
		"hex",                          // Elixir and Erlang both publish here
		"multiple",                     // names a set of managers, not an ecosystem
		"generic",                      // the fallback type names no ecosystem
		"",                             // no type at all
		"a-detector-type-nobody-knows", // the open vocabulary keeps its say
	} {
		if got := EcosystemForPURLType(purlType); got != EcosystemUnknown {
			t.Errorf("EcosystemForPURLType(%q) = %q, want a refusal", purlType, got)
		}
	}
}

// TestEcosystemForPURLTypeRoundTripsTheEcosystemVocabulary walks the SDK's
// full ecosystem registry and fails when an ecosystem cannot be recovered
// from the purl type it mints — the drift guard that makes an addition to
// the vocabulary a test failure rather than a silently unknown ecosystem.
// The two exceptions are the documented ambiguities, asserted as such so
// neither can be "fixed" into a guess.
func TestEcosystemForPURLTypeRoundTripsTheEcosystemVocabulary(t *testing.T) {
	// pkg:hex serves Elixir and Erlang, so an Elixir package's own type
	// cannot name it back; pkg:maven covers Scala too, and resolves to
	// maven by grandfathering (dropping the row would regress every Java
	// SBOM to unknown). See the purlkit table comment for both.
	ambiguous := map[Ecosystem]Ecosystem{
		EcosystemElixir: EcosystemUnknown,
		EcosystemScala:  EcosystemMaven,
	}
	for _, item := range ecosystemRegistry {
		ecosystem := item.Ecosystem
		if ecosystem == EcosystemUnknown {
			continue
		}
		purlType := PackageURLTypeForValues(ecosystem)
		want, isAmbiguous := ambiguous[ecosystem]
		if !isAmbiguous {
			want = ecosystem
		}
		if got := EcosystemForPURLType(purlType); got != want {
			if isAmbiguous {
				t.Errorf("ecosystem %q mints %q, which now resolves to %q; the documented answer is %q", ecosystem, purlType, got, want)
				continue
			}
			t.Errorf("ecosystem %q mints %q, which resolves back to %q", ecosystem, purlType, got)
		}
	}
}
