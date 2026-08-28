package sdk

import (
	"testing"

	"github.com/bomly-dev/bomly-sdk/purlkit"
)

// TestPackageURLTypeForValuesMatchesLegacySwitch pins that the purlkit table
// answers exactly like the historical root switch for every token either of
// them knows, so the S3 delegation is behavior-preserving by construction.
// legacyPackageURLTypeSwitch is the frozen pre-delegation implementation; it
// exists only for this parity check.
func TestPackageURLTypeForValuesMatchesLegacySwitch(t *testing.T) {
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
			if got != want {
				t.Errorf("PackageURLTypeForValues(%q, %q) = %q, legacy = %q", first, second, got, want)
			}
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
