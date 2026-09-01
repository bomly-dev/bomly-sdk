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
// The sourceType argument is a license *type* -- "declared" or "concluded" --
// and always was: it is written to PackageLicense.Type, and this module's own
// callers pass "declared". A matcher that wants to record which component
// supplied the claim wants NormalizeLicenseSetFrom instead. The two are
// independent facts, and one argument carrying both is what let a matcher name
// reach a field that turned out to be a closed vocabulary.
func NormalizeLicenseSet(values []string, sourceType string) []sdk.PackageLicense {
	return NormalizeLicenseSetFrom(values, sourceType, "")
}

// NormalizeLicenseSetFrom is NormalizeLicenseSet with provenance: source names
// the component that supplied the claim, such as a matcher name, and reaches
// PackageLicense.Source.
//
// It exists as a second entry point rather than a wider signature because
// NormalizeLicenseSet is exported and its meaning is not this release's to
// change. Passing "" for source is exactly NormalizeLicenseSet.
func NormalizeLicenseSetFrom(values []string, licenseType, source string) []sdk.PackageLicense {
	// Blanks and duplicates are dropped before anything is parsed, so the
	// aggregate parsing gate below measures the values classification will
	// actually see — a raw slice padded with blanks or repeats must not
	// cost a small unique set its classification.
	unique := make([]string, 0, len(values))
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
		unique = append(unique, normalized)
	}
	// Classification is one parser invocation per value, so the batch is
	// gated by spdxkit's aggregate limits. Over the limit nothing is
	// dropped and nothing masquerades: every value keeps its trimmed Value
	// and stays unclassified free text (SPDXExpression empty).
	classify := spdxkit.BatchWithinBounds(unique)
	out := make([]sdk.PackageLicense, 0, len(unique))
	for _, normalized := range unique {
		license := sdk.PackageLicense{
			Value: normalized,
			// Two independent facts, two fields. The matcher name is
			// provenance; the license type is the kind of claim. They shared
			// Type until Type became a closed vocabulary, at which point the
			// model gate silently dropped the matcher name and emptied the
			// "licenses[].source" field the CLI documents.
			Source: source,
			Type:   sdk.LicenseType(licenseType),
		}
		if !classify {
			out = append(out, license)
			continue
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
