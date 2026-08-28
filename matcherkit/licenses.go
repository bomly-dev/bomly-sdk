// Package matcherkit contains shared helper functions for matcher
// implementations.
package matcherkit

import (
	"strings"

	sdk "github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/spdxkit"
)

// MissingLicensePackages returns the packages eligible for external license lookup.
func MissingLicensePackages(packages []*sdk.Package) []*sdk.Package {
	eligible := make([]*sdk.Package, 0, len(packages))
	for _, pkg := range packages {
		if pkg == nil || len(pkg.Licenses) > 0 {
			continue
		}
		if strings.TrimSpace(pkg.Name) == "" || strings.TrimSpace(pkg.Version) == "" {
			continue
		}
		eligible = append(eligible, pkg)
	}
	return eligible
}

// NormalizeLicenseSet converts raw license strings into Bomly package
// licenses, classifying each value by validating it (ADR-0035 in bomly-cli's
// dev-docs/adr, enforced at write time via spdxkit). Value preserves the
// input after whitespace trimming — nothing else is altered — while
// SPDXExpression is set only when
// the value actually is SPDX: the canonical current spelling for a
// license-list identifier (deprecated entries fold to their replacements),
// the validated expression otherwise. Free text such as "non-standard"
// leaves SPDXExpression empty instead of masquerading as an expression.
func NormalizeLicenseSet(values []string, sourceType string) []sdk.PackageLicense {
	out := make([]sdk.PackageLicense, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		license := sdk.PackageLicense{
			Value: normalized,
			Type:  sdk.LicenseType(sourceType),
		}
		switch spdxkit.Classify(normalized) {
		case spdxkit.ClassIdentifier:
			if canonical, ok := spdxkit.CanonicalIdentifier(normalized); ok {
				license.SPDXExpression = canonical
			}
		case spdxkit.ClassExpression:
			license.SPDXExpression = spdxkit.CanonicalExpression(normalized)
		}
		out = append(out, license)
	}
	return out
}
