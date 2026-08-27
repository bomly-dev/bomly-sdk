package purlkit

import "strings"

// TypeForValues maps ecosystem / package-manager / package-type tokens to a
// package-url type. It is the one authority for this mapping (ADR-0038); the
// root PackageURLTypeForValues delegates here after converting its typed
// arguments to strings.
//
// The explicit switch below is consulted for every value before the loose
// fallback runs, so the most specific mapping wins regardless of the order
// the caller passes ecosystem / package manager / package type in. The
// fallback then returns the first non-empty value verbatim, which is only
// correct where the Bomly identifier happens to be the purl type as well
// (npm, maven, apk, rpm, ...). Any ecosystem whose purl type differs from its
// Bomly name needs an explicit case here — without one we emit a type that is
// not in the purl spec, and consumers keyed on the type (OSV, SBOM ingest)
// silently fail to match. See bomly-cli issue #317.
//
// Ecosystems that span more than one registry are the exception: erlang
// covers both Hex (rebar) and OTP (*.app), so it is mapped at the
// package-manager level only. A bare erlang value with no manager to
// disambiguate keeps the non-spec pkg:erlang rather than guessing a registry
// the package may not be published to.
func TypeForValues(values ...string) string {
	for _, value := range values {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "nuget", "dotnet":
			return "nuget"
		case "cargo", "rust":
			return "cargo"
		case "pub", "dart":
			return "pub"
		case "cocoapods":
			// Deliberately no "swift" case: swift is itself a purl type, and
			// adding one here would beat cocoapods whenever the ecosystem is
			// checked before the package manager.
			return "cocoapods"
		case "swiftpm":
			return "swift"
		case "github-actions", "githubactions":
			return "githubactions"
		case "conan", "cpp":
			return "conan"
		case "mix", "hex", "elixir", "rebar":
			// Elixir (mix) and Erlang (rebar) both resolve from Hex.
			return "hex"
		case "otp":
			// OTP applications are discovered from *.app manifests. They ship
			// with the runtime or the release rather than resolving from Hex,
			// so they get their own type — the same one Syft emits for them.
			// Claiming Hex here would let a name collision with a real Hex
			// package produce a false advisory match.
			return "otp"
		case "haskell", "cabal", "stack", "hackage":
			return "hackage"
		case "r", "r-package", "cran":
			return "cran"
		case "ocaml", "opam":
			return "opam"
		case "dpkg", "deb":
			return "deb"
		case "sbt", "scala":
			return "maven"
		case "ruby", "gem", "rubygems", "bundler":
			return "gem"
		case "php", "composer":
			return "composer"
		case "python", "pypi", "pip", "pipenv", "poetry", "uv":
			return "pypi"
		}
	}
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" {
			continue
		}
		switch normalized {
		case "go", "gomod":
			return "golang"
		default:
			return normalized
		}
	}
	return "generic"
}

// purlTypeEcosystems is the reverse join for purl types whose spec name
// differs from the Bomly ecosystem token. Values are canonical Bomly
// ecosystem tokens (the string values of the root Ecosystem constants).
//
// Types that two ecosystems share are deliberately absent, and
// EcosystemForType refuses them rather than guessing. pkg:hex is emitted for
// both Elixir (mix) and Erlang (rebar), and nothing in the PURL says which;
// guessing would relabel every round-tripped Erlang dependency as Elixir.
// pkg:maven covers Scala too and is ambiguous in the same way, but consumers
// resolved it to maven long before this table existed; dropping it now would
// regress every Java SBOM to unknown, so it stays by grandfathering, with the
// ambiguity recorded here.
var purlTypeEcosystems = map[string]string{
	"golang": "go",
	// pkg:otp, unlike pkg:hex, names exactly one ecosystem.
	"otp":           "erlang",
	"hackage":       "haskell",
	"cran":          "r",
	"opam":          "ocaml",
	"deb":           "dpkg",
	"cargo":         "rust",
	"nuget":         "dotnet",
	"pypi":          "python",
	"gem":           "ruby",
	"composer":      "php",
	"pub":           "dart",
	"conan":         "cpp",
	"cocoapods":     "swift",
	"swift":         "swift",
	"maven":         "maven",
	"githubactions": "github-actions",
}

// EcosystemForType returns the Bomly ecosystem token for a purl type whose
// spec name differs from the ecosystem token, and refuses ambiguous types.
// EcosystemForType("hex") returns ("", false) by decision, not omission —
// see the table comment. Callers that also accept identity mappings (purl
// types that are themselves Bomly ecosystem tokens, such as "npm") layer
// their own ecosystem parsing over this table; the kit stays string-typed
// and does not duplicate the ecosystem vocabulary.
func EcosystemForType(purlType string) (ecosystem string, ok bool) {
	ecosystem, ok = purlTypeEcosystems[strings.ToLower(strings.TrimSpace(purlType))]
	return ecosystem, ok
}

// canonicalEcosystems folds ecosystem, package-manager, and tool aliases to
// the canonical Bomly ecosystem token. One table, replacing the divergent
// per-purpose copies that grew in the root package; a row's absence is as
// deliberate as its presence — "hex" is refused because the Hex registry
// serves both Elixir and Erlang.
var canonicalEcosystems = map[string]string{
	"npm": "npm", "pnpm": "npm", "yarn": "npm", "bun": "npm",
	"go": "go", "gomod": "go", "golang": "go",
	"python": "python", "pip": "python", "pipenv": "python", "poetry": "python",
	"uv": "python", "setup.py": "python", "pypi": "python",
	"rust": "rust", "cargo": "rust",
	"maven": "maven", "gradle": "maven",
	"dotnet": "dotnet", "nuget": "dotnet",
	"dart": "dart", "pub": "dart",
	"swift": "swift", "swiftpm": "swift", "cocoapods": "swift",
	"cpp": "cpp", "conan": "cpp",
	"elixir": "elixir", "mix": "elixir",
	"erlang": "erlang", "rebar": "erlang", "otp": "erlang",
	"scala": "scala", "sbt": "scala",
	"php": "php", "composer": "php", "packagist": "php",
	"ruby": "ruby", "gem": "ruby", "bundler": "ruby", "rubygems": "ruby",
	"haskell": "haskell", "cabal": "haskell", "stack": "haskell", "hackage": "haskell",
	"r": "r", "r-package": "r", "cran": "r",
	"ocaml": "ocaml", "opam": "ocaml",
	"dpkg": "dpkg", "deb": "dpkg",
	"github-actions": "github-actions", "githubactions": "github-actions",
}

// CanonicalEcosystem folds the first recognizable value to its canonical
// Bomly ecosystem token, checking values in the order given (pass ecosystem,
// then package manager, then package type, so the most authoritative value
// wins). It returns ok=false when no value is recognized — including for
// "hex", whose refusal is deliberate.
func CanonicalEcosystem(values ...string) (ecosystem string, ok bool) {
	for _, value := range values {
		if canonical, found := canonicalEcosystems[strings.ToLower(strings.TrimSpace(value))]; found {
			return canonical, true
		}
	}
	return "", false
}
