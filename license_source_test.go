package sdk

import (
	"encoding/json"
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
		got, _ := PackageLicense{Value: "MIT", Source: source}.Normalized()
		if got.Source != "" {
			t.Errorf("source %q survived as %q", source, got.Source)
		}
	}
	// A clean token publishes, and surrounding space is trimmed rather than
	// costing the value.
	got, _ := PackageLicense{Value: "MIT", Source: "  external-depsdev  "}.Normalized()
	if got.Source != "external-depsdev" {
		t.Errorf("Source = %q, want the trimmed token", got.Source)
	}
}

// TestLicenseSourceIsOmitEmpty pins that a license with no source writes the
// exact bytes it wrote before the field existed.
func TestLicenseSourceIsOmitEmpty(t *testing.T) {
	data, err := json.Marshal(PackageLicense{Value: "MIT"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(data), "source") {
		t.Errorf("a license with no source wrote the field: %s", data)
	}
}
