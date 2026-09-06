package sdk

import (
	"encoding/json"
	"os"
	"path/filepath"
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

// specTypesOutsideTheEcosystemVocabulary names every purl type the
// specification defines that EcosystemForPURLType deliberately does not
// answer, with the reason. A type absent from both this list and the join is
// the drift this file exists to catch.
//
// Most of these are not registries at all -- a container image, a VCS
// checkout, a model hub -- and Bomly has no ecosystem token to give them.
// Two are different in kind and are called out as such.
var specTypesOutsideTheEcosystemVocabulary = map[string]string{
	// The one refusal that is a decision rather than an absence: Hex serves
	// Elixir and Erlang alike, and nothing in the PURL says which.
	"hex": "ambiguous — the Hex registry serves both Elixir and Erlang",

	// A GitHub repository is not a GitHub Action. EcosystemGitHub means
	// Actions, which Bomly and Syft key on the non-spec pkg:githubactions;
	// answering EcosystemGitHub for pkg:github would relabel every source
	// checkout as a workflow dependency.
	"github": "names a repository, not the Actions ecosystem",

	"bazel":            "a build system, not a package registry",
	"bitbucket":        "names a repository, not a registry",
	"bitnami":          "a distribution channel Bomly has no ecosystem for",
	"chrome-extension": "no Bomly ecosystem",
	"cpan":             "Perl, which Bomly's vocabulary does not cover",
	"docker":           "a container image, not a package",
	"generic":          "the fallback type names no ecosystem by construction",
	"git":              "a VCS checkout, not a registry",
	"huggingface":      "a model hub, not a package registry",
	"julia":            "no Bomly ecosystem",
	"mlflow":           "a model registry, not a package registry",
	"oci":              "a container image, not a package",
	"qpkg":             "no Bomly ecosystem",
	"swid":             "a software identification tag, not a registry",
	"vcpkg":            "a C/C++ registry Bomly reads through conan",
	"vscode-extension": "no Bomly ecosystem",
	"yocto":            "no Bomly ecosystem",
}

// TestEcosystemForPURLTypeCoversTheSpecTypeVocabulary is the second drift
// guard, aimed the other way from the round-trip above: that one fails when
// Bomly's vocabulary grows a row, this one when the *specification* does.
// A type the spec defines must either resolve to an ecosystem the SDK knows
// or be named above with a reason — a new type lands in neither and fails
// here, which is what a hand-maintained mapping cannot do for itself.
//
// It reads the purl-spec definitions vendored for purlkit's typeProfiles
// differential test (issue #67, refreshed by scripts/vendor-purl-spec.sh)
// rather than vendoring a second copy: one set of files, two readers, and
// no chance of the two disagreeing about what the spec says.
func TestEcosystemForPURLTypeCoversTheSpecTypeVocabulary(t *testing.T) {
	definitions, err := filepath.Glob(filepath.Join("purlkit", "testdata", "purl-spec", "types", "*-definition.json"))
	if err != nil {
		t.Fatalf("glob the vendored purl-spec types: %v", err)
	}
	if len(definitions) == 0 {
		t.Fatal("no vendored purl-spec type definitions found; the testdata moved and this guard is asserting nothing")
	}
	seen := make(map[string]bool, len(definitions))
	for _, path := range definitions {
		// The file name carries the type, but the document states it; read
		// the document, so a renamed file cannot quietly change which type
		// is under test.
		raw, err := os.ReadFile(path) //nolint:gosec // a vendored test fixture path
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var definition struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &definition); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		if definition.Type == "" {
			t.Fatalf("%s states no type", path)
		}
		seen[definition.Type] = true

		resolved := EcosystemForPURLType(definition.Type)
		reason, excluded := specTypesOutsideTheEcosystemVocabulary[definition.Type]
		switch {
		case excluded && resolved != EcosystemUnknown:
			t.Errorf("pkg:%s is listed as having no ecosystem (%s) but resolves to %q", definition.Type, reason, resolved)
		case !excluded && resolved == EcosystemUnknown:
			t.Errorf("pkg:%s resolves to no ecosystem and is not listed as one that should; add the row or record why there is none", definition.Type)
		case !excluded:
			if _, err := ParseEcosystem(string(resolved)); err != nil {
				t.Errorf("pkg:%s resolves to %q, which ParseEcosystem rejects: %v", definition.Type, resolved, err)
			}
		}
	}
	// A stale exclusion is drift too: the spec dropped a type, or it was
	// spelled wrong here and has been excusing nothing ever since.
	for purlType := range specTypesOutsideTheEcosystemVocabulary {
		if !seen[purlType] {
			t.Errorf("%q is listed as a spec type without an ecosystem, but the vendored spec defines no such type", purlType)
		}
	}
}
