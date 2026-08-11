package sdk

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/emptypb"
)

func detectorModuleFixture() *DetectorModule {
	return &DetectorModule{
		Descriptor: DetectorDescriptor{Name: "fake-detector"},
		Support:    []PackageManagerSupport{Support(PackageManagerNPM, "package-lock.json")},
		New: func(context.Context, HostContext) (Detector, error) {
			return &fakeModuleDetector{}, nil
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

// fakeHostContext is a minimal in-test HostContext.
type fakeHostContext struct{}

func (fakeHostContext) Logger() *zap.Logger             { return zap.NewNop() }
func (fakeHostContext) HTTPClient() *HTTPClientProvider { return nil }
func (fakeHostContext) Runtime() RuntimeInfo            { return RuntimeInfo{Execution: ExecutionManaged} }
func (fakeHostContext) DecodeConfig(any) error          { return nil }

// fakeModuleDetector implements Detector (and InstallFirstDetector) for the
// adapter round-trip tests.
type fakeModuleDetector struct {
	readyErr  error
	installed bool
}

func (d *fakeModuleDetector) Descriptor() DetectorDescriptor {
	return DetectorDescriptor{Name: "fake-detector"}
}

func (d *fakeModuleDetector) PackageManagerSupport() []PackageManagerSupport {
	return []PackageManagerSupport{Support(PackageManagerNPM, "package.json")}
}

func (d *fakeModuleDetector) Ready(context.Context, DetectionRequest) error {
	return d.readyErr
}

func (d *fakeModuleDetector) Applicable(_ context.Context, req DetectionRequest) (bool, error) {
	return req.PackageManager == PackageManagerNPM, nil
}

func (d *fakeModuleDetector) ResolveGraph(_ context.Context, req DetectionRequest) (DetectionResult, error) {
	return DetectionResult{DetectorName: "fake-detector", SubprojectInfo: req.Subproject}, nil
}

func (d *fakeModuleDetector) Install(context.Context, DetectionRequest) error {
	d.installed = true
	return nil
}

func TestServedDetectorModuleRoundTrip(t *testing.T) {
	constructed := 0
	fake := &fakeModuleDetector{}
	module := &DetectorModule{
		Descriptor: DetectorDescriptor{Name: "fake-detector"},
		Support:    []PackageManagerSupport{Support(PackageManagerNPM, "package-lock.json")},
		New: func(_ context.Context, host HostContext) (Detector, error) {
			if host == nil {
				t.Fatal("expected host context")
			}
			constructed++
			return fake, nil
		},
	}
	server := &serviceServer{detector: newServedDetectorModule(module, fakeHostContext{})}

	out, err := server.DetectorDescriptor(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("DetectorDescriptor: %v", err)
	}
	descriptor, err := unmarshalBytes[DetectorDescriptor](out.Value)
	if err != nil || descriptor.Name != "fake-detector" {
		t.Fatalf("descriptor round-trip mismatch: %+v err=%v", descriptor, err)
	}
	if constructed != 0 {
		t.Fatalf("descriptor must not construct the component, constructed=%d", constructed)
	}

	supportOut, err := server.DetectorPackageManagerSupport(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("DetectorPackageManagerSupport: %v", err)
	}
	support, err := unmarshalBytes[[]PackageManagerSupport](supportOut.Value)
	if err != nil || len(*support) != 1 || (*support)[0].PackageManager != PackageManagerNPM {
		t.Fatalf("support round-trip mismatch: %+v err=%v", support, err)
	}
	if (*support)[0].EvidencePatterns[0] != "package-lock.json" {
		t.Fatalf("expected module support (not component support) to be served: %+v", *support)
	}
	if constructed != 0 {
		t.Fatalf("module-declared support must not construct the component, constructed=%d", constructed)
	}

	readyOut, err := server.DetectorReady(context.Background(), encodeRequest(t, &DetectRequest{}))
	if err != nil {
		t.Fatalf("DetectorReady: %v", err)
	}
	ready, err := unmarshalBytes[ReadyResponse](readyOut.Value)
	if err != nil || !ready.Ready || ready.Reason != "" {
		t.Fatalf("ready round-trip mismatch: %+v err=%v", ready, err)
	}
	if constructed != 1 {
		t.Fatalf("expected exactly one construction, got %d", constructed)
	}

	fake.readyErr = errors.New("node executable not found on PATH")
	readyOut, err = server.DetectorReady(context.Background(), encodeRequest(t, &DetectRequest{}))
	if err != nil {
		t.Fatalf("DetectorReady (not ready): %v", err)
	}
	ready, err = unmarshalBytes[ReadyResponse](readyOut.Value)
	if err != nil || ready.Ready || ready.Reason != "node executable not found on PATH" {
		t.Fatalf("not-ready mapping mismatch: %+v err=%v", ready, err)
	}

	applicableOut, err := server.DetectorApplicable(context.Background(), encodeRequest(t, &DetectRequest{PackageManager: PackageManagerNPM}))
	if err != nil {
		t.Fatalf("DetectorApplicable: %v", err)
	}
	applicable, err := unmarshalBytes[ApplicableResponse](applicableOut.Value)
	if err != nil || !applicable.Applicable {
		t.Fatalf("applicable round-trip mismatch: %+v err=%v", applicable, err)
	}

	detectOut, err := server.Detect(context.Background(), encodeRequest(t, &DetectRequest{PackageManager: PackageManagerNPM}))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	result, err := unmarshalBytes[DetectResponse](detectOut.Value)
	if err != nil || result.DetectorName != "fake-detector" {
		t.Fatalf("detect round-trip mismatch: %+v err=%v", result, err)
	}

	installOut, err := server.DetectorInstall(context.Background(), encodeRequest(t, &DetectRequest{}))
	if err != nil {
		t.Fatalf("DetectorInstall: %v", err)
	}
	install, err := unmarshalBytes[InstallResponse](installOut.Value)
	if err != nil || !install.Performed || !fake.installed {
		t.Fatalf("install round-trip mismatch: %+v installed=%v err=%v", install, fake.installed, err)
	}

	if constructed != 1 {
		t.Fatalf("expected the component to be constructed once, got %d", constructed)
	}
}

func TestServedDetectorModuleConstructionError(t *testing.T) {
	module := &DetectorModule{
		Descriptor: DetectorDescriptor{Name: "fake-detector"},
		New: func(context.Context, HostContext) (Detector, error) {
			return nil, errors.New("boom")
		},
	}
	server := &serviceServer{detector: newServedDetectorModule(module, fakeHostContext{})}
	if _, err := server.DetectorReady(context.Background(), encodeRequest(t, &DetectRequest{})); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected construction error, got %v", err)
	}
	if _, err := server.Detect(context.Background(), encodeRequest(t, &DetectRequest{})); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected construction error on Detect, got %v", err)
	}
}

// fakeModuleMatcher implements Matcher for the adapter mapping test.
type fakeModuleMatcher struct{}

func (fakeModuleMatcher) Descriptor() MatcherDescriptor {
	return MatcherDescriptor{Name: "fake-matcher"}
}

func (fakeModuleMatcher) Ready(context.Context, MatchRequest) error { return nil }

func (fakeModuleMatcher) Applicable(context.Context, MatchRequest) (bool, error) {
	return true, nil
}

func (fakeModuleMatcher) Match(context.Context, MatchRequest) (MatchResult, error) {
	return MatchResult{MatcherStats: MatcherStats{Name: "fake-matcher", MatchedPackages: 3}}, nil
}

func TestServedMatcherModuleRoundTrip(t *testing.T) {
	module := &MatcherModule{
		Descriptor: MatcherDescriptor{Name: "fake-matcher"},
		New: func(context.Context, HostContext) (Matcher, error) {
			return fakeModuleMatcher{}, nil
		},
	}
	server := &serviceServer{matcher: newServedMatcherModule(module, fakeHostContext{})}

	out, err := server.MatcherDescriptor(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("MatcherDescriptor: %v", err)
	}
	descriptor, err := unmarshalBytes[MatcherDescriptor](out.Value)
	if err != nil || descriptor.Name != "fake-matcher" {
		t.Fatalf("descriptor round-trip mismatch: %+v err=%v", descriptor, err)
	}

	readyOut, err := server.MatcherReady(context.Background(), encodeRequest(t, &MatchRequest{}))
	if err != nil {
		t.Fatalf("MatcherReady: %v", err)
	}
	ready, err := unmarshalBytes[ReadyResponse](readyOut.Value)
	if err != nil || !ready.Ready {
		t.Fatalf("ready round-trip mismatch: %+v err=%v", ready, err)
	}

	matchOut, err := server.Match(context.Background(), encodeRequest(t, &MatchRequest{}))
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	result, err := unmarshalBytes[MatchResponse](matchOut.Value)
	if err != nil || result.MatcherStats.MatchedPackages != 3 {
		t.Fatalf("match round-trip mismatch: %+v err=%v", result, err)
	}
}
