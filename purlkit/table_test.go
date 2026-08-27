package purlkit

import "testing"

func TestTypeForValuesLegacyParity(t *testing.T) {
	// Every row of the historical root mapping, pinned so a table edit is a
	// chosen, reviewed change rather than an accident.
	cases := map[string]string{
		"nuget": "nuget", "dotnet": "nuget",
		"cargo": "cargo", "rust": "cargo",
		"pub": "pub", "dart": "pub",
		"cocoapods":      "cocoapods",
		"swiftpm":        "swift",
		"github-actions": "githubactions", "githubactions": "githubactions",
		"conan": "conan", "cpp": "conan",
		"mix": "hex", "hex": "hex", "elixir": "hex", "rebar": "hex",
		"otp":     "otp",
		"haskell": "hackage", "cabal": "hackage", "stack": "hackage", "hackage": "hackage",
		"r": "cran", "r-package": "cran", "cran": "cran",
		"ocaml": "opam", "opam": "opam",
		"dpkg": "deb", "deb": "deb",
		"sbt": "maven", "scala": "maven",
		"ruby": "gem", "gem": "gem", "rubygems": "gem", "bundler": "gem",
		"php": "composer", "composer": "composer",
		"python": "pypi", "pypi": "pypi", "pip": "pypi", "pipenv": "pypi", "poetry": "pypi", "uv": "pypi",
		// Fallback pass: verbatim identities and the go alias.
		"go": "golang", "gomod": "golang",
		"npm": "npm", "maven": "maven", "apk": "apk", "rpm": "rpm",
		// No recognizable value at all.
		"": "generic",
	}
	for input, want := range cases {
		if got := TypeForValues(input); got != want {
			t.Errorf("TypeForValues(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestTypeForValuesMostSpecificWins(t *testing.T) {
	// The explicit switch is consulted for every value before the fallback,
	// so ordering of ecosystem vs manager must not matter.
	if got := TypeForValues("swift", "cocoapods"); got != "cocoapods" {
		t.Fatalf("TypeForValues(swift, cocoapods) = %q, want cocoapods", got)
	}
	if got := TypeForValues("cocoapods", "swift"); got != "cocoapods" {
		t.Fatalf("TypeForValues(cocoapods, swift) = %q, want cocoapods", got)
	}
	if got := TypeForValues("erlang", "rebar"); got != "hex" {
		t.Fatalf("TypeForValues(erlang, rebar) = %q, want hex", got)
	}
	if got := TypeForValues("erlang"); got != "erlang" {
		t.Fatalf("TypeForValues(erlang) = %q, want verbatim erlang", got)
	}
}

func TestEcosystemForTypeRows(t *testing.T) {
	cases := map[string]string{
		"golang": "go", "otp": "erlang", "hackage": "haskell", "cran": "r",
		"opam": "ocaml", "deb": "dpkg", "cargo": "rust", "nuget": "dotnet",
		"pypi": "python", "gem": "ruby", "composer": "php", "pub": "dart",
		"conan": "cpp", "cocoapods": "swift", "swift": "swift",
		"maven": "maven", "githubactions": "github-actions",
	}
	for input, want := range cases {
		got, ok := EcosystemForType(input)
		if !ok || got != want {
			t.Errorf("EcosystemForType(%q) = (%q, %v), want (%q, true)", input, got, ok, want)
		}
	}
}

func TestEcosystemForTypeRefusesHex(t *testing.T) {
	// pkg:hex serves both Elixir and Erlang, and nothing in the PURL says
	// which. The refusal IS the decision (ADR-0038): no second table may
	// quietly decide otherwise. This test pins the refusal.
	if got, ok := EcosystemForType("hex"); ok {
		t.Fatalf("EcosystemForType(hex) = (%q, true), want refusal", got)
	}
	if got, ok := EcosystemForType("erlang"); ok {
		t.Fatalf("EcosystemForType(erlang) = (%q, true), want refusal (non-spec type)", got)
	}
	if _, ok := EcosystemForType("unknown-type"); ok {
		t.Fatal("EcosystemForType(unknown-type) succeeded, want refusal")
	}
}

func TestCanonicalEcosystem(t *testing.T) {
	cases := map[string]string{
		"pnpm": "npm", "bun": "npm", "gomod": "go", "golang": "go",
		"pip": "python", "uv": "python", "cargo": "rust", "gradle": "maven",
		"nuget": "dotnet", "pub": "dart", "swiftpm": "swift", "cocoapods": "swift",
		"conan": "cpp", "mix": "elixir", "rebar": "erlang", "otp": "erlang",
		"sbt": "scala", "packagist": "php", "bundler": "ruby",
		"hackage": "haskell", "cran": "r", "opam": "ocaml", "deb": "dpkg",
		"githubactions": "github-actions",
	}
	for input, want := range cases {
		got, ok := CanonicalEcosystem(input)
		if !ok || got != want {
			t.Errorf("CanonicalEcosystem(%q) = (%q, %v), want (%q, true)", input, got, ok, want)
		}
	}
	if got, ok := CanonicalEcosystem("hex"); ok {
		t.Fatalf("CanonicalEcosystem(hex) = (%q, true), want refusal — Hex serves two ecosystems", got)
	}
	if got, ok := CanonicalEcosystem("nothing", "cargo"); !ok || got != "rust" {
		t.Fatalf("CanonicalEcosystem(nothing, cargo) = (%q, %v), want (rust, true)", got, ok)
	}
}
