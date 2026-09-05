package sdk

import (
	"strings"
	"testing"
)

// TestLicenseSourceIsGated pins the source's domain. It is a component name,
// and "My Matcher" is a valid component -- so gating this as a single short
// token would silently erase the provenance of a legitimately named matcher.
// What is enforced is what publication needs, which is the same domain
// descriptor validation holds a name to (TestComponentNameIsBounded pins the
// two agreeing).
func TestLicenseSourceIsGated(t *testing.T) {
	// Refused: a control character would corrupt SPDX's line-oriented tag
	// form, and an unbounded value is not a name.
	for _, source := range []string{
		"with\ttab", "with\nnewline", strings.Repeat("s", maxLicenseSourceLength+1),
	} {
		got, ok := PackageLicense{Value: "MIT", Source: source}.Normalized()
		if !ok {
			t.Fatalf("source %q took the whole license with it", source)
		}
		if got.Source != "" {
			t.Errorf("source %q survived as %q", source, got.Source)
		}
	}
	// Kept: whitespace inside a name is legal, and a name longer than a
	// vocabulary token is still a name.
	for _, source := range []string{
		"external-depsdev",
		"My Matcher",
		strings.Repeat("s", maxVocabularyTokenLength+1),
	} {
		got, ok := PackageLicense{Value: "MIT", Source: source}.Normalized()
		if !ok || got.Source != source {
			t.Errorf("source %q was erased (ok=%v, got %q); a valid component name must survive", source, ok, got.Source)
		}
	}
	// Surrounding space is trimmed rather than costing the value.
	got, ok := PackageLicense{Value: "MIT", Source: "  external-depsdev  "}.Normalized()
	if !ok {
		t.Fatal("a license with a clean source was dropped")
	}
	if got.Source != "external-depsdev" {
		t.Errorf("Source = %q, want the trimmed name", got.Source)
	}
}

// TestLicenseSourceSurvivesAMerge pins the merge class. Source is not part of
// the merge identity, so an unsourced copy of a claim and a matcher-sourced
// copy are one claim -- and without a fill-gaps rule, whichever arrived first
// decided whether the provenance survived. That made the fix order-dependent
// through Package.MergeFrom and SetDetectionLicenses.
func TestLicenseSourceSurvivesAMerge(t *testing.T) {
	unsourced := PackageLicense{Value: "MIT", SPDXExpression: "MIT", Type: LicenseTypeDeclared}
	sourced := PackageLicense{Value: "MIT", SPDXExpression: "MIT", Type: LicenseTypeDeclared, Source: "external-depsdev"}

	for _, tc := range []struct {
		name          string
		first, second []PackageLicense
	}{
		{"unsourced first", []PackageLicense{unsourced}, []PackageLicense{sourced}},
		{"sourced first", []PackageLicense{sourced}, []PackageLicense{unsourced}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			merged := MergeLicenses(tc.first, tc.second)
			if len(merged) != 1 {
				t.Fatalf("merged into %d claims, want one: %+v", len(merged), merged)
			}
			if merged[0].Source != "external-depsdev" {
				t.Errorf("Source = %q, want the provenance carried whichever side had it", merged[0].Source)
			}
		})
	}
}
