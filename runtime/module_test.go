package runtime

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/bomly-dev/bomly-sdk/httpkit"

	sdk "github.com/bomly-dev/bomly-sdk"
)

// fakeHostContext is a minimal in-test HostContext.
type fakeHostContext struct{}

func (fakeHostContext) Logger() *zap.Logger                 { return zap.NewNop() }
func (fakeHostContext) HTTPClient() *httpkit.ClientProvider { return nil }
func (fakeHostContext) Runtime() sdk.RuntimeInfo {
	return sdk.RuntimeInfo{Execution: sdk.ExecutionManaged}
}
func (fakeHostContext) DecodeConfig(any) error { return nil }

// fakeModuleDetector implements Detector (and InstallFirstDetector) for the
// adapter round-trip tests.
type fakeModuleDetector struct {
	readyErr  error
	installed bool
}

func (d *fakeModuleDetector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{Name: "fake-detector"}
}

func (d *fakeModuleDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerNPM, "package.json")}
}

func (d *fakeModuleDetector) Ready(context.Context, sdk.DetectionRequest) error {
	return d.readyErr
}

func (d *fakeModuleDetector) Applicable(_ context.Context, req sdk.DetectionRequest) (bool, error) {
	return req.PackageManager == sdk.PackageManagerNPM, nil
}

func (d *fakeModuleDetector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	return sdk.DetectionResult{DetectorName: "fake-detector", SubprojectInfo: req.Subproject}, nil
}

func (d *fakeModuleDetector) Install(context.Context, sdk.DetectionRequest) error {
	d.installed = true
	return nil
}

func TestServedDetectorModuleRoundTrip(t *testing.T) {
	constructed := 0
	fake := &fakeModuleDetector{}
	module := &sdk.DetectorModule{
		Descriptor: sdk.DetectorDescriptor{Name: "fake-detector"},
		Support:    []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerNPM, "package-lock.json")},
		New: func(_ context.Context, host sdk.HostContext) (sdk.Detector, error) {
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
	descriptor, err := unmarshalBytes[sdk.DetectorDescriptor](out.Value)
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
	support, err := unmarshalBytes[[]sdk.PackageManagerSupport](supportOut.Value)
	if err != nil || len(*support) != 1 || (*support)[0].PackageManager != sdk.PackageManagerNPM {
		t.Fatalf("support round-trip mismatch: %+v err=%v", support, err)
	}
	if (*support)[0].EvidencePatterns[0] != "package-lock.json" {
		t.Fatalf("expected module support (not component support) to be served: %+v", *support)
	}
	if constructed != 0 {
		t.Fatalf("module-declared support must not construct the component, constructed=%d", constructed)
	}

	readyOut, err := server.DetectorReady(context.Background(), encodeRequest(t, &sdk.DetectRequest{}))
	if err != nil {
		t.Fatalf("DetectorReady: %v", err)
	}
	ready, err := unmarshalBytes[sdk.ReadyResponse](readyOut.Value)
	if err != nil || !ready.Ready || ready.Reason != "" {
		t.Fatalf("ready round-trip mismatch: %+v err=%v", ready, err)
	}
	if constructed != 1 {
		t.Fatalf("expected exactly one construction, got %d", constructed)
	}

	fake.readyErr = errors.New("node executable not found on PATH")
	readyOut, err = server.DetectorReady(context.Background(), encodeRequest(t, &sdk.DetectRequest{}))
	if err != nil {
		t.Fatalf("DetectorReady (not ready): %v", err)
	}
	ready, err = unmarshalBytes[sdk.ReadyResponse](readyOut.Value)
	if err != nil || ready.Ready || ready.Reason != "node executable not found on PATH" {
		t.Fatalf("not-ready mapping mismatch: %+v err=%v", ready, err)
	}

	applicableOut, err := server.DetectorApplicable(context.Background(), encodeRequest(t, &sdk.DetectRequest{PackageManager: sdk.PackageManagerNPM}))
	if err != nil {
		t.Fatalf("DetectorApplicable: %v", err)
	}
	applicable, err := unmarshalBytes[sdk.ApplicableResponse](applicableOut.Value)
	if err != nil || !applicable.Applicable {
		t.Fatalf("applicable round-trip mismatch: %+v err=%v", applicable, err)
	}

	detectOut, err := server.Detect(context.Background(), encodeRequest(t, &sdk.DetectRequest{PackageManager: sdk.PackageManagerNPM}))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	result, err := unmarshalBytes[sdk.DetectResponse](detectOut.Value)
	if err != nil || result.DetectorName != "fake-detector" {
		t.Fatalf("detect round-trip mismatch: %+v err=%v", result, err)
	}

	installOut, err := server.DetectorInstall(context.Background(), encodeRequest(t, &sdk.DetectRequest{}))
	if err != nil {
		t.Fatalf("DetectorInstall: %v", err)
	}
	install, err := unmarshalBytes[sdk.InstallResponse](installOut.Value)
	if err != nil || !install.Performed || !fake.installed {
		t.Fatalf("install round-trip mismatch: %+v installed=%v err=%v", install, fake.installed, err)
	}

	if constructed != 1 {
		t.Fatalf("expected the component to be constructed once, got %d", constructed)
	}
}

func TestServedDetectorModuleConstructionError(t *testing.T) {
	module := &sdk.DetectorModule{
		Descriptor: sdk.DetectorDescriptor{Name: "fake-detector"},
		New: func(context.Context, sdk.HostContext) (sdk.Detector, error) {
			return nil, errors.New("boom")
		},
	}
	server := &serviceServer{detector: newServedDetectorModule(module, fakeHostContext{})}
	if _, err := server.DetectorReady(context.Background(), encodeRequest(t, &sdk.DetectRequest{})); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected construction error, got %v", err)
	}
	if _, err := server.Detect(context.Background(), encodeRequest(t, &sdk.DetectRequest{})); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected construction error on Detect, got %v", err)
	}
}

// fakeModuleMatcher implements Matcher for the adapter mapping test.
type fakeModuleMatcher struct{}

func (fakeModuleMatcher) Descriptor() sdk.MatcherDescriptor {
	return sdk.MatcherDescriptor{Name: "fake-matcher"}
}

func (fakeModuleMatcher) Ready(context.Context, sdk.MatchRequest) error { return nil }

func (fakeModuleMatcher) Applicable(context.Context, sdk.MatchRequest) (bool, error) {
	return true, nil
}

func (fakeModuleMatcher) Match(context.Context, sdk.MatchRequest) (sdk.MatchResult, error) {
	return sdk.MatchResult{MatcherStats: sdk.MatcherStats{Name: "fake-matcher", MatchedPackages: 3}}, nil
}

func TestServedMatcherModuleRoundTrip(t *testing.T) {
	module := &sdk.MatcherModule{
		Descriptor: sdk.MatcherDescriptor{Name: "fake-matcher"},
		New: func(context.Context, sdk.HostContext) (sdk.Matcher, error) {
			return fakeModuleMatcher{}, nil
		},
	}
	server := &serviceServer{matcher: newServedMatcherModule(module, fakeHostContext{})}

	out, err := server.MatcherDescriptor(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("MatcherDescriptor: %v", err)
	}
	descriptor, err := unmarshalBytes[sdk.MatcherDescriptor](out.Value)
	if err != nil || descriptor.Name != "fake-matcher" {
		t.Fatalf("descriptor round-trip mismatch: %+v err=%v", descriptor, err)
	}

	readyOut, err := server.MatcherReady(context.Background(), encodeRequest(t, &sdk.MatchRequest{}))
	if err != nil {
		t.Fatalf("MatcherReady: %v", err)
	}
	ready, err := unmarshalBytes[sdk.ReadyResponse](readyOut.Value)
	if err != nil || !ready.Ready {
		t.Fatalf("ready round-trip mismatch: %+v err=%v", ready, err)
	}

	matchOut, err := server.Match(context.Background(), encodeRequest(t, &sdk.MatchRequest{}))
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	result, err := unmarshalBytes[sdk.MatchResponse](matchOut.Value)
	if err != nil || result.MatcherStats.MatchedPackages != 3 {
		t.Fatalf("match round-trip mismatch: %+v err=%v", result, err)
	}
}
