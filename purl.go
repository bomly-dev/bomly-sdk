package sdk

import (
	"strings"

	"github.com/bomly-dev/bomly-sdk/purlkit"
)

// CanonicalizePackageURL normalizes a package URL string when possible.
// It delegates to purlkit, the single home for package-URL behavior.
func CanonicalizePackageURL(value string) string {
	return purlkit.Canonicalize(value)
}

// BuildPackageURL builds and normalizes a package URL from its parts.
func BuildPackageURL(purlType, namespace, name, version string) string {
	purlType = strings.TrimSpace(strings.ToLower(purlType))
	name = strings.Trim(strings.ReplaceAll(strings.TrimSpace(name), "\\", "/"), "/")
	namespace = strings.Trim(strings.ReplaceAll(strings.TrimSpace(namespace), "\\", "/"), "/")
	version = strings.TrimSpace(version)
	if purlType == "" || name == "" {
		return ""
	}
	built, err := purlkit.Build(purlkit.PURL{Type: purlType, Namespace: namespace, Name: name, Version: version})
	if err != nil {
		// The library rejected the parts: there is no valid package URL to
		// mint, and emitting a hand-concatenated one the library refused
		// would put an invalid identity on the wire.
		return ""
	}
	return built
}

// PackageURLTypeForValues maps ecosystem/build-system values to a package-url type.
//
// The explicit switch below is the authority: it is consulted for every value
// before the loose fallback runs, so the most specific mapping wins regardless
// of the order the caller passes ecosystem / package manager / package type in.
// The fallback then returns the first non-empty value verbatim, which is only
// correct where the Bomly identifier happens to be the purl type as well (npm,
// maven, apk, rpm, ...). Any ecosystem whose purl type differs from its Bomly
// name needs an explicit case here — without one we emit a type that is not in
// the purl spec, and consumers keyed on the type (OSV, SBOM ingest) silently
// fail to match. See issue #317.
//
// Ecosystems that span more than one registry are the exception: erlang covers
// both Hex (rebar) and OTP (*.app), so it is mapped at the package-manager
// level only. A bare erlang value with no manager to disambiguate keeps the
// non-spec pkg:erlang rather than guessing a registry the package may not be
// published to.
func PackageURLTypeForValues(values ...any) string {
	converted := make([]string, 0, len(values))
	for _, value := range values {
		converted = append(converted, packageURLTypeValue(value))
	}
	return purlkit.TypeForValues(converted...)
}

// legacyPackageURLTypeSwitch is retained only by its parity test, which pins
// that the purlkit table matches the historical mapping row for row.
func legacyPackageURLTypeSwitch(values ...any) string {
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(packageURLTypeValue(value)))
		switch normalized {
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
		normalized := strings.ToLower(strings.TrimSpace(packageURLTypeValue(value)))
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

func packageURLTypeValue(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case Ecosystem:
		return string(v)
	case PackageManager:
		return v.Name()
	case PackageType:
		return string(v)
	case Language:
		return string(v)
	default:
		return ""
	}
}

// CanonicalPackageURLFromParts returns the canonical package URL derived from
// raw identity fields. existingPURL takes precedence when it canonicalizes.
func CanonicalPackageURLFromParts(existingPURL string, ecosystem Ecosystem, packageManager PackageManager, typ PackageType, org, name, version string) string {
	return (Coordinates{
		PURL:           existingPURL,
		Ecosystem:      ecosystem,
		PackageManager: packageManager,
		Type:           typ,
		Org:            org,
		Name:           name,
		Version:        version,
	}).CanonicalPURL()
}

// GenericPURL returns a pkg:generic package URL for the identity, for the
// case where the ecosystem's own type profile rejects the coordinates.
//
// It is deliberately separate from CanonicalPURL: that answers "what is this
// package's canonical identity in its own ecosystem", and answering it with a
// generic URL would make every caller unable to tell the two apart. Node
// construction is the only place that reaches for this, and it records a
// warning when it does.
//
// A qualifier names the type that could not express the package. Two
// ecosystems whose profiles both reject otherwise identical coordinates would
// otherwise mint the same identity -- a bare Swift "internal-tools@2.0.0" and
// a bare Go one both becoming pkg:generic/internal-tools@2.0.0 -- and folding
// two distinct packages into one node is a worse outcome than the loose type
// this fallback already accepts. A degraded identity still has to be an
// identity.
//
// A qualifier rather than the namespace, because coordinates are projected
// from the identity verbatim once it is minted: a discriminator in the
// namespace comes back as Coordinates.Org, so a bare Swift package would read
// as organization "swift" and display as "swift:internal-tools" -- an
// organization no manifest declared. A qualifier is part of the identity, so
// it keeps the two records distinct, and it is not projected, so the
// coordinates still say what the detector found. It also rides the wire,
// which is what lets the warning below be derived after a decode.
func (i Coordinates) GenericPURL() string {
	if i.Type == PackageTypeManifest {
		return ""
	}
	name := strings.TrimSpace(i.Name)
	if name == "" {
		return ""
	}
	failedType := strings.TrimSpace(PackageURLTypeForValues(i.Ecosystem, i.PackageManager, i.Type))
	if failedType == "" || failedType == genericPURLType {
		return ""
	}
	built, err := purlkit.Build(purlkit.PURL{
		Type:       genericPURLType,
		Namespace:  strings.TrimSpace(i.Org),
		Name:       name,
		Version:    strings.TrimSpace(i.Version),
		Qualifiers: []purlkit.Qualifier{{Key: GenericFallbackTypeQualifier, Value: failedType}},
	})
	if err != nil {
		return ""
	}
	return built
}

// genericPURLType is the package URL type a degraded identity falls back to.
const genericPURLType = "generic"

// GenericFallbackTypeQualifier names the package URL type that could not
// express a package whose identity fell back to pkg:generic.
//
// It is prefixed because it is this project's, not the specification's: a
// consumer reading an exported document should be able to tell a Bomly
// annotation from a purl-spec qualifier at a glance.
const GenericFallbackTypeQualifier = "bomly_source_type"

// genericFallbackType reports the type a generic identity fell back from, and
// whether it fell back at all.
func genericFallbackType(purl purlkit.PURL) (string, bool) {
	if !strings.EqualFold(purl.Type, genericPURLType) {
		return "", false
	}
	for _, qualifier := range purl.Qualifiers {
		if strings.EqualFold(qualifier.Key, GenericFallbackTypeQualifier) && qualifier.Value != "" {
			return qualifier.Value, true
		}
	}
	return "", false
}

// CanonicalPURL returns the canonical package URL for the identity.
func (i Coordinates) CanonicalPURL() string {
	if canonical := CanonicalizePackageURL(i.PURL); canonical != "" {
		return canonical
	}
	if i.Type == PackageTypeManifest {
		return ""
	}

	name := strings.TrimSpace(i.Name)
	if name == "" {
		return ""
	}

	purlType := PackageURLTypeForValues(i.Ecosystem, i.PackageManager, i.Type)
	namespace := strings.TrimSpace(i.Org)
	if purlType == "golang" && namespace == "" {
		parts := strings.Split(strings.ReplaceAll(name, "\\", "/"), "/")
		if len(parts) > 1 {
			namespace = strings.Join(parts[:len(parts)-1], "/")
			name = parts[len(parts)-1]
		}
	}

	return BuildPackageURL(purlType, namespace, name, i.Version)
}

// PackageURLBase strips version, qualifiers, and subpath from a package URL.
// It delegates to purlkit.Base, which works on the parsed structure — the
// previous string surgery mishandled subpath-carrying and version-less
// package URLs.
func PackageURLBase(value string) string {
	return purlkit.Base(value)
}
