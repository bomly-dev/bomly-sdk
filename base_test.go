package sdk

import (
	"context"
	"testing"
)

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
