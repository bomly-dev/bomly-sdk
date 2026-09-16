package plugin

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk/model"
)

func detectorModuleFixture() *DetectorModule {
	return &DetectorModule{
		Descriptor: DetectorDescriptor{Name: "fake-detector"},
		Support:    []PackageManagerSupport{Support(model.PackageManagerNPM, "package-lock.json")},
		New: func(context.Context, HostContext) (Detector, error) {
			return minimalDetector{}, nil
		},
	}
}

func TestValidateModule(t *testing.T) {
	matcherModule := &MatcherModule{
		Descriptor: MatcherDescriptor{Name: "fake-matcher"},
		New: func(context.Context, HostContext) (Matcher, error) {
			return nil, errors.New("unused")
		},
	}
	auditorModule := &AuditorModule{
		Descriptor: AuditorDescriptor{Name: "fake-auditor"},
		New: func(context.Context, HostContext) (Auditor, error) {
			return nil, errors.New("unused")
		},
	}
	analyzerModule := &AnalyzerModule{
		Descriptor: AnalyzerDescriptor{Name: "fake-analyzer"},
		New: func(context.Context, HostContext) (Analyzer, error) {
			return nil, errors.New("unused")
		},
	}

	cases := []struct {
		name    string
		module  Module
		wantErr string
	}{
		{
			name:   "valid detector",
			module: Module{Kind: PluginKindDetector, Detector: detectorModuleFixture()},
		},
		{
			name:   "valid matcher",
			module: Module{Kind: PluginKindMatcher, Matcher: matcherModule},
		},
		{
			name:   "valid auditor",
			module: Module{Kind: PluginKindAuditor, Auditor: auditorModule},
		},
		{
			name:   "valid analyzer",
			module: Module{Kind: PluginKindAnalyzer, Analyzer: analyzerModule},
		},
		{
			name:    "no role",
			module:  Module{Kind: PluginKindDetector},
			wantErr: "exactly one role",
		},
		{
			name: "two roles",
			module: Module{
				Kind:     PluginKindDetector,
				Detector: detectorModuleFixture(),
				Matcher:  matcherModule,
			},
			wantErr: "exactly one role",
		},
		{
			name:    "kind role mismatch",
			module:  Module{Kind: PluginKindMatcher, Detector: detectorModuleFixture()},
			wantErr: "requires the Matcher role",
		},
		{
			name:    "invalid kind",
			module:  Module{Kind: PluginKind("bogus"), Detector: detectorModuleFixture()},
			wantErr: "is invalid",
		},
		{
			name: "valid detector with target kinds",
			module: Module{Kind: PluginKindDetector, Detector: func() *DetectorModule {
				module := detectorModuleFixture()
				module.TargetKinds = []ExecutionTargetKind{ExecutionTargetFilesystem, ExecutionTargetGitRepository}
				return module
			}()},
		},
		{
			name: "empty target kind",
			module: Module{Kind: PluginKindDetector, Detector: func() *DetectorModule {
				module := detectorModuleFixture()
				module.TargetKinds = []ExecutionTargetKind{ExecutionTargetFilesystem, ""}
				return module
			}()},
			wantErr: "target kinds must not contain empty values",
		},
		{
			name: "missing constructor",
			module: Module{Kind: PluginKindDetector, Detector: &DetectorModule{
				Descriptor: DetectorDescriptor{Name: "fake"},
			}},
			wantErr: "constructor is required",
		},
		{
			name: "invalid descriptor",
			module: Module{Kind: PluginKindAnalyzer, Analyzer: &AnalyzerModule{
				Descriptor: AnalyzerDescriptor{Name: "   "},
				New: func(context.Context, HostContext) (Analyzer, error) {
					return nil, errors.New("unused")
				},
			}},
			wantErr: "descriptor",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateModule(tc.module)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid module, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}
