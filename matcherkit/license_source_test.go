package matcherkit_test

import (
	"testing"

	sdk "github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/matcherkit"
)

// TestLicenseSourceSurvivesTheGate pins the fix for a silent regression the
// v0.7.0 model introduced. This kit wrote its matcher name into
// sdk.PackageLicense.Type; once Type became the closed declared/concluded
// vocabulary, the model's gate dropped the value -- silently emptying the
// "licenses[].source" field the CLI documents and publishes.
//
// The two are independent facts: a deps.dev license is declared *and* sourced
// from deps.dev. Sharing one field is what made the loss possible.
func TestLicenseSourceSurvivesTheGate(t *testing.T) {
	licenses := matcherkit.NormalizeLicenseSet([]string{"MIT"}, "external-depsdev")
	if len(licenses) != 1 {
		t.Fatalf("got %d licenses, want 1", len(licenses))
	}
	if licenses[0].Source != "external-depsdev" {
		t.Errorf("Source = %q, want the matcher name to survive", licenses[0].Source)
	}
	if licenses[0].Type != sdk.LicenseTypeDeclared {
		t.Errorf("Type = %q, want a registry-reported license to be declared", licenses[0].Type)
	}
	// And it survives the model's own gate, which is where it was lost.
	normalized, ok := licenses[0].Normalized()
	if !ok || normalized.Source != "external-depsdev" {
		t.Errorf("after Normalized: Source = %q ok=%v", normalized.Source, ok)
	}
}
