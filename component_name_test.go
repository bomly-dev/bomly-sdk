package sdk

import (
	"strings"
	"testing"
)

// A component name reaches published documents as a license source, and the
// source gate bounds it. Descriptor validation used to ask only that a name be
// non-blank, so a 257-byte matcher was a valid component whose provenance the
// source gate then erased. The two are one domain now, enforced where the
// contract lives.
func TestComponentNameIsBounded(t *testing.T) {
	validators := map[string]func(name string) error{
		"detector": func(name string) error { return ValidateDetectorDescriptor(&DetectorDescriptor{Name: name}) },
		"matcher":  func(name string) error { return ValidateMatcherDescriptor(&MatcherDescriptor{Name: name}) },
		"auditor":  func(name string) error { return ValidateAuditorDescriptor(&AuditorDescriptor{Name: name}) },
		"analyzer": func(name string) error { return ValidateAnalyzerDescriptor(&AnalyzerDescriptor{Name: name}) },
	}

	longest := strings.Repeat("n", maxComponentNameLength)
	accepted := []string{
		"external-depsdev",
		"My Matcher",
		" padded ",
		longest,
	}
	// Checked as stored, not trimmed: validation does not rewrite the name,
	// so what passes is what gets marshaled. Trimming first let a control
	// character at an edge through and let unbounded padding ride past a
	// bound that exists to be a resource limit.
	rejected := []string{
		longest + "n",
		" " + longest + " ",
		"\nmatcher",
		"matcher\t",
		"with\ttab",
		"with\nnewline",
		"with\x7fdelete",
		"bad\xffutf8",
	}

	for kind, validate := range validators {
		t.Run(kind, func(t *testing.T) {
			for _, name := range accepted {
				if err := validate(name); err != nil {
					t.Errorf("name %q rejected: %v", name, err)
				}
			}
			for _, name := range rejected {
				if err := validate(name); err == nil {
					t.Errorf("name %q accepted; want it refused at the descriptor gate", name)
				}
			}
		})
	}

	// The contract the bound exists for: every name that validates as a
	// component survives as a license source, so provenance is never erased
	// one layer down from where the name was accepted.
	for _, name := range accepted {
		if err := validators["matcher"](name); err != nil {
			t.Fatal(err)
		}
		got, ok := PackageLicense{Value: "MIT", Source: name}.Normalized()
		if !ok || got.Source != strings.TrimSpace(name) {
			t.Errorf("source %q erased (ok=%v, got %q) for a name descriptor validation accepts", name, ok, got.Source)
		}
	}
}
