package sdk

import (
	"strings"
	"unicode"

	"github.com/bomly-dev/bomly-sdk/purlkit"
)

const (
	normMetadataAppliedKey         = "bomly.normalization.applied"
	normMetadataOriginalNameKey    = "bomly.normalization.original_name"
	normMetadataOriginalOrgKey     = "bomly.normalization.original_org"
	normMetadataOriginalVersionKey = "bomly.normalization.original_version"
)

// NormalizeCoordinates applies ecosystem-aware identity normalization to
// the coordinate fields in place and returns which rules applied. It is the
// pre-minting step of node construction — normalize, then mint the
// canonical package URL, then construct — and records nothing itself: the
// constructors store the provenance breadcrumbs on the node.
func NormalizeCoordinates(pkg *Coordinates) []string {
	if pkg == nil {
		return nil
	}

	applied := make([]string, 0, 4)

	pkg.Name = strings.TrimSpace(pkg.Name)
	pkg.Org = strings.TrimSpace(pkg.Org)
	pkg.Version = strings.TrimSpace(pkg.Version)
	pkg.PURL = strings.TrimSpace(pkg.PURL)
	if canonicalPURL := CanonicalizePackageURL(pkg.PURL); canonicalPURL != "" && canonicalPURL != pkg.PURL {
		pkg.PURL = canonicalPURL
		applied = append(applied, "purl")
	}

	switch normEffectiveEcosystem(pkg) {
	case EcosystemNPM:
		applied = append(applied, normNPM(pkg)...)
	case EcosystemPython:
		applied = append(applied, normPython(pkg)...)
	case EcosystemRust:
		applied = append(applied, normRust(pkg)...)
	case EcosystemMaven:
		applied = append(applied, normMaven(pkg)...)
	case EcosystemGo:
		applied = append(applied, normGo(pkg)...)
	case EcosystemPHP:
		applied = append(applied, normComposer(pkg)...)
	}

	// Version casing is the library's call, per purl type, and this is where
	// the coordinates adopt it. Deriving it from the canonical package URL
	// delegates the whole rule rather than transcribing which types fold
	// case: whatever packageurl-go does inside Normalize, the coordinates
	// follow, today for huggingface alone and automatically for any type it
	// adds.
	//
	// Without this the two normalization paths disagreed for exactly that
	// type: NewDependencyNode projects its coordinates from the minted
	// identity and so lowercased, while a direct NormalizeCoordinates call
	// left the version as written.
	if canonical := pkg.CanonicalPURL(); canonical != "" {
		if parsed, err := purlkit.Parse(canonical); err == nil {
			if parsed.Version != "" && parsed.Version != pkg.Version {
				pkg.Version = parsed.Version
				applied = append(applied, "version")
			}
		}
	}

	return applied
}

func normNPM(pkg *Coordinates) []string {
	applied := make([]string, 0, 2)
	if scope, name, ok := normSplitScopedNPMName(pkg.Name); ok {
		pkg.Org = scope
		pkg.Name = name
		applied = append(applied, "npm-scope")
	}
	if normalizedOrg := strings.TrimPrefix(strings.ToLower(pkg.Org), "@"); normalizedOrg != pkg.Org {
		pkg.Org = normalizedOrg
		applied = append(applied, "org")
	}
	if normalizedName := strings.ToLower(pkg.Name); normalizedName != pkg.Name {
		pkg.Name = normalizedName
		applied = append(applied, "name")
	}
	return applied
}

func normPython(pkg *Coordinates) []string {
	normalized := normCanonicalizePythonName(pkg.Name)
	if normalized == pkg.Name {
		return nil
	}
	pkg.Name = normalized
	return []string{"name"}
}

func normRust(pkg *Coordinates) []string {
	normalized := normCollapseRepeated(strings.ToLower(strings.ReplaceAll(pkg.Name, "_", "-")), '-')
	if normalized == pkg.Name {
		return nil
	}
	pkg.Name = normalized
	return []string{"name"}
}

func normMaven(pkg *Coordinates) []string {
	applied := make([]string, 0, 2)
	if normalizedOrg := strings.ToLower(pkg.Org); normalizedOrg != pkg.Org {
		pkg.Org = normalizedOrg
		applied = append(applied, "org")
	}
	if normalizedName := strings.TrimSpace(pkg.Name); normalizedName != pkg.Name {
		pkg.Name = normalizedName
		applied = append(applied, "name")
	}
	return applied
}

func normGo(pkg *Coordinates) []string {
	applied := make([]string, 0, 2)
	if normalizedOrg := normNormalizeSlashPath(pkg.Org); normalizedOrg != pkg.Org {
		pkg.Org = normalizedOrg
		applied = append(applied, "org")
	}
	if normalizedName := normNormalizeSlashPath(pkg.Name); normalizedName != pkg.Name {
		pkg.Name = normalizedName
		applied = append(applied, "name")
	}
	return applied
}

func normComposer(pkg *Coordinates) []string {
	if len(pkg.Version) > 1 && (pkg.Version[0] == 'v' || pkg.Version[0] == 'V') {
		pkg.Version = pkg.Version[1:]
		return []string{"version"}
	}
	return nil
}

func normEffectiveEcosystem(pkg *Coordinates) Ecosystem {
	if pkg == nil {
		return EcosystemUnknown
	}
	canonical, ok := purlkit.CanonicalEcosystem(
		string(pkg.Ecosystem),
		pkg.PackageManager.Name(),
		string(pkg.Type),
	)
	if !ok {
		return EcosystemUnknown
	}
	return Ecosystem(canonical)
}

func normSplitScopedNPMName(name string) (string, string, bool) {
	trimmed := strings.TrimSpace(name)
	if !strings.HasPrefix(trimmed, "@") {
		return "", "", false
	}
	parts := strings.SplitN(strings.TrimPrefix(trimmed, "@"), "/", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", false
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}

func normCanonicalizePythonName(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return ""
	}
	replaced := strings.Map(func(r rune) rune {
		switch {
		case r == '-' || r == '_' || r == '.' || unicode.IsSpace(r):
			return '-'
		default:
			return unicode.ToLower(r)
		}
	}, lower)
	return normCollapseRepeated(strings.Trim(replaced, "-"), '-')
}

func normNormalizeSlashPath(value string) string {
	trimmed := strings.Trim(strings.ReplaceAll(strings.TrimSpace(value), "\\", "/"), "/")
	for strings.Contains(trimmed, "//") {
		trimmed = strings.ReplaceAll(trimmed, "//", "/")
	}
	return trimmed
}

// Version casing is delegated, not decided here.
//
// This used to lowercase any version containing a letter, which is wrong for
// nearly every ecosystem and lossy in the direction that matters: a Maven
// "1.0-SNAPSHOT" became "1.0-snapshot" in the coordinates, and that is the
// value an SBOM publishes and a user reads.
//
// packageurl-go owns the rule and applies it per type inside Normalize, which
// every minted identity already runs through (purlkit.Build ->
// normalizeAndRender -> PackageURL.Normalize). Its typeAdjustVersion
// lowercases exactly one type -- huggingface -- and keeps every other version
// verbatim, which is what the purl specification says. NormalizeCoordinates
// reads the answer back off the canonical package URL rather than
// transcribing that set, so the two paths agree and an upstream addition is
// picked up rather than missed.
//
// TestVersionCasingMatchesPackageURLLibrary reads the library's own source and
// fails if that set grows, so a change upstream is a test failure rather than
// a silent divergence.

func normCollapseRepeated(value string, separator rune) string {
	if value == "" {
		return value
	}
	var builder strings.Builder
	builder.Grow(len(value))
	lastWasSeparator := false
	for _, r := range value {
		if r == separator {
			if lastWasSeparator {
				continue
			}
			lastWasSeparator = true
		} else {
			lastWasSeparator = false
		}
		builder.WriteRune(r)
	}
	return builder.String()
}

func normUniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
