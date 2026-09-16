package sdk

import (
	"context"
	"strings"
	"testing"
)

func TestValidateDetectorDescriptorRemediationCapabilities(t *testing.T) {
	tests := []struct {
		name       string
		capability RemediationCapability
		wantError  string
	}{
		{
			name: "valid",
			capability: RemediationCapability{
				SupportedManagers: []PackageManager{PackageManagerNPM},
				Actions:           []RemediationAction{RemediationActionDirectBump},
			},
		},
		{
			name:       "missing manager",
			capability: RemediationCapability{Actions: []RemediationAction{RemediationActionDirectBump}},
			wantError:  "package manager",
		},
		{
			name: "empty manager",
			capability: RemediationCapability{
				SupportedManagers: []PackageManager{PackageManagerUnknown},
				Actions:           []RemediationAction{RemediationActionDirectBump},
			},
			wantError: "empty",
		},
		{
			name: "missing action",
			capability: RemediationCapability{
				SupportedManagers: []PackageManager{PackageManagerNPM},
			},
			wantError: "action",
		},
		{
			name: "central-only action",
			capability: RemediationCapability{
				SupportedManagers: []PackageManager{PackageManagerNPM},
				Actions:           []RemediationAction{RemediationActionManualReview},
			},
			wantError: "invalid",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateDetectorDescriptor(&DetectorDescriptor{
				Name:                    "test-detector",
				RemediationCapabilities: []RemediationCapability{test.capability},
			})
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("ValidateDetectorDescriptor() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("ValidateDetectorDescriptor() error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestProtocolV1DetectorDescriptorLeavesRemediationOptional(t *testing.T) {
	descriptor := DetectorDescriptor{
		Name:              "legacy-detector",
		SupportedManagers: []PackageManager{PackageManagerNPM},
	}
	if err := ValidateDetectorDescriptor(&descriptor); err != nil {
		t.Fatalf("ValidateDetectorDescriptor() rejected legacy descriptor: %v", err)
	}
	if descriptor.RemediationCapabilities != nil {
		t.Fatalf("legacy descriptor gained remediation capabilities: %#v", descriptor)
	}
}

func TestDetectorDescriptorCloneDeepCopiesRemediationCapabilities(t *testing.T) {
	descriptor := DetectorDescriptor{
		Name: "test-detector",
		RemediationCapabilities: []RemediationCapability{{
			SupportedManagers: []PackageManager{PackageManagerNPM},
			Actions:           []RemediationAction{RemediationActionDirectBump},
		}},
	}
	clone := descriptor.Clone()
	clone.RemediationCapabilities[0].SupportedManagers[0] = PackageManagerGoMod
	clone.RemediationCapabilities[0].Actions[0] = RemediationActionLockfileRefresh
	if descriptor.RemediationCapabilities[0].SupportedManagers[0] != PackageManagerNPM ||
		descriptor.RemediationCapabilities[0].Actions[0] != RemediationActionDirectBump {
		t.Fatalf("Clone() shared remediation capability slices: %#v", descriptor)
	}
}

func TestValidateAnalyzerDescriptorNil(t *testing.T) {
	if err := ValidateAnalyzerDescriptor(nil); err == nil {
		t.Fatal("expected error for nil analyzer descriptor")
	}
	if err := ValidateAnalyzerDescriptor(&AnalyzerDescriptor{Name: "ok"}); err != nil {
		t.Fatalf("valid descriptor rejected: %v", err)
	}
}

// minimalDetector exercises the embedding pattern: only identity and the
// action method are implemented; lifecycle methods come from BaseDetector.
type minimalDetector struct {
	BaseDetector
}

func (minimalDetector) Descriptor() DetectorDescriptor {
	return DetectorDescriptor{Name: "minimal"}
}

func (minimalDetector) PackageManagerSupport() []PackageManagerSupport { return nil }

func (minimalDetector) ResolveGraph(context.Context, DetectionRequest) (DetectionResult, error) {
	return DetectionResult{}, nil
}

type minimalMatcher struct {
	BaseMatcher
}

func (minimalMatcher) Descriptor() MatcherDescriptor {
	return MatcherDescriptor{Name: "minimal"}
}

func (minimalMatcher) Match(context.Context, MatchRequest) (MatchResult, error) {
	return MatchResult{}, nil
}

type minimalAuditor struct {
	BaseAuditor
}

func (minimalAuditor) Descriptor() AuditorDescriptor {
	return AuditorDescriptor{Name: "minimal"}
}

func (minimalAuditor) Audit(context.Context, AuditRequest) (AuditResult, error) {
	return AuditResult{}, nil
}

type minimalAnalyzer struct {
	BaseAnalyzer
}

func (minimalAnalyzer) Descriptor() AnalyzerDescriptor {
	return AnalyzerDescriptor{Name: "minimal"}
}

func (minimalAnalyzer) Analyze(context.Context, AnalyzeRequest) (AnalyzeResult, error) {
	return AnalyzeResult{}, nil
}

func TestBaseTypesSatisfyInterfaces(t *testing.T) {
	var _ Detector = minimalDetector{}
	var _ Matcher = minimalMatcher{}
	var _ Auditor = minimalAuditor{}
	var _ Analyzer = minimalAnalyzer{}

	ctx := context.Background()
	if err := (minimalDetector{}).Ready(ctx, DetectionRequest{}); err != nil {
		t.Fatalf("BaseDetector.Ready: %v", err)
	}
	ok, err := minimalMatcher{}.Applicable(ctx, MatchRequest{})
	if err != nil || !ok {
		t.Fatalf("BaseMatcher.Applicable = %v, %v; want true, nil", ok, err)
	}
	if err := (minimalAuditor{}).Ready(ctx, AuditRequest{}); err != nil {
		t.Fatalf("BaseAuditor.Ready: %v", err)
	}
	ok, err = minimalAnalyzer{}.Applicable(ctx, AnalyzeRequest{})
	if err != nil || !ok {
		t.Fatalf("BaseAnalyzer.Applicable = %v, %v; want true, nil", ok, err)
	}
}

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
