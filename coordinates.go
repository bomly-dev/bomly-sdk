package sdk

import "strings"

// Coordinates is the shared identity view embedded by Dependency and Package.
// It intentionally excludes graph-only fields (scopes, locations, package refs)
// and enrichment-only fields (licenses, vulnerabilities, scorecard) so
// detection-time graph nodes and matching-stage package records remain distinct
// domain models.
type Coordinates struct {
	PURL           string         `json:"purl,omitempty"`
	Ecosystem      Ecosystem      `json:"ecosystem,omitempty"`
	PackageManager PackageManager `json:"package_manager,omitempty"`
	Type           PackageType    `json:"type,omitempty"`
	Org            string         `json:"org,omitempty"`
	Name           string         `json:"name,omitempty"`
	Version        string         `json:"version,omitempty"`
	Language       Language       `json:"language,omitempty"`
}

// QualifiedName returns the package name prefixed with its organization when present.
func (i Coordinates) QualifiedName() string {
	return qualifiedName(i.Org, i.Name)
}

// DisplayName returns the package name in its ecosystem-native form:
// "@org/name" for npm-family packages, "org/name" for path-style ecosystems
// (Go, Composer), and "org:name" otherwise. Unlike QualifiedName it is a
// presentation label only and must never be used as an identity key.
func (i Coordinates) DisplayName() string {
	if i.Org == "" || i.Name == "" {
		return qualifiedName(i.Org, i.Name)
	}
	switch i.displayEcosystem() {
	case EcosystemNPM:
		return "@" + i.Org + "/" + i.Name
	case EcosystemGo, EcosystemPHP:
		return i.Org + "/" + i.Name
	default:
		return i.Org + ":" + i.Name
	}
}

// EcosystemName returns the package name in the form its ecosystem uses as an
// identity: "@org/name" for npm, "org:name" for Maven-family coordinates, and
// "org/name" for the path-style namespaced ecosystems (Go, Composer, Swift,
// GitHub Actions). This is the name external advisory databases, SBOM
// documents, and scanners such as Grype and Syft key on, so anything building a
// lookup for a package must derive it from here rather than from the bare Name
// — Name alone drops the npm scope and matches the unscoped package's
// advisories.
//
// Joining is opt-in per ecosystem, and everything else keeps the bare Name,
// because Org is not always part of the package name. For OS packages Org is
// the distro that shipped the package (`Org: "alpine"` from
// `pkg:apk/alpine/libcrypto3`), and Grype's distro-namespace matchers query
// `libcrypto3`; joining would miss every OS advisory. The same holds for any
// other ecosystem whose PURL namespace names a vendor or channel rather than
// part of the package's own identity.
func (i Coordinates) EcosystemName() string {
	org := strings.TrimSpace(i.Org)
	name := strings.TrimSpace(i.Name)
	if org == "" || name == "" {
		return qualifiedName(org, name)
	}
	switch i.displayEcosystem() {
	case EcosystemNPM:
		return "@" + strings.TrimPrefix(org, "@") + "/" + name
	case EcosystemMaven, EcosystemScala:
		return org + ":" + name
	case EcosystemGo, EcosystemPHP, EcosystemSwift, EcosystemGitHub:
		return org + "/" + name
	default:
		return name
	}
}

// displayEcosystem resolves the effective ecosystem for display formatting,
// falling back to the package-manager name when Ecosystem is unset (e.g.
// pnpm/yarn graphs that only carry a manager identifier).
func (i Coordinates) displayEcosystem() Ecosystem {
	for _, candidate := range []string{string(i.Ecosystem), i.PackageManager.Name(), string(i.Type)} {
		switch strings.ToLower(strings.TrimSpace(candidate)) {
		case string(EcosystemNPM), "pnpm", "yarn", "bun":
			return EcosystemNPM
		case string(EcosystemGo), "gomod", "golang":
			return EcosystemGo
		case string(EcosystemPHP), "composer", "packagist":
			return EcosystemPHP
		case string(EcosystemMaven), "gradle":
			return EcosystemMaven
		case string(EcosystemScala), "sbt":
			return EcosystemScala
		case string(EcosystemSwift), "swiftpm":
			return EcosystemSwift
		case string(EcosystemGitHub), "githubactions":
			return EcosystemGitHub
		}
	}
	return i.Ecosystem
}
