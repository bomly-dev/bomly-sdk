package sdk

import (
	"strings"
	"testing"
)

// TestLicenseSourceIsGated pins that a source is held to the token rule: it is
// written into published output, so it cannot carry whitespace, control
// characters, or unbounded length.
func TestLicenseSourceIsGated(t *testing.T) {
	for _, source := range []string{
		"two words", "with\ttab", "with\nnewline", strings.Repeat("s", 4096),
	} {
		got, ok := PackageLicense{Value: "MIT", Source: source}.Normalized()
		if !ok {
			// Without this the assertion below passes when the whole license
			// was dropped, since Source is then empty for the wrong reason.
			t.Fatalf("source %q took the whole license with it", source)
		}
		if got.Source != "" {
			t.Errorf("source %q survived as %q", source, got.Source)
		}
	}
	// A clean token publishes, and surrounding space is trimmed rather than
	// costing the value.
	got, ok := PackageLicense{Value: "MIT", Source: "  external-depsdev  "}.Normalized()
	if !ok {
		t.Fatal("a license with a clean source was dropped")
	}
	if got.Source != "external-depsdev" {
		t.Errorf("Source = %q, want the trimmed token", got.Source)
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
