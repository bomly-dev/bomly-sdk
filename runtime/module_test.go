package runtime

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/bomly-dev/bomly-sdk/httpkit"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

// fakeHostContext is a minimal in-test HostContext.
type fakeHostContext struct{}

func (fakeHostContext) Logger() *zap.Logger                 { return zap.NewNop() }
func (fakeHostContext) HTTPClient() *httpkit.ClientProvider { return nil }
func (fakeHostContext) Runtime() plugin.RuntimeInfo {
	return plugin.RuntimeInfo{Execution: plugin.ExecutionManaged}
}
func (fakeHostContext) DecodeConfig(any) error { return nil }

// fakeModuleDetector implements Detector (and InstallFirstDetector) for the
// adapter round-trip tests.
type fakeModuleDetector struct {
	readyErr  error
	installed bool
}

func (d *fakeModuleDetector) Descriptor() plugin.DetectorDescriptor {
	return plugin.DetectorDescriptor{Name: "fake-detector"}
}

func (d *fakeModuleDetector) PackageManagerSupport() []plugin.PackageManagerSupport {
	return []plugin.PackageManagerSupport{plugin.Support(model.PackageManagerNPM, "package.json")}
}

func (d *fakeModuleDetector) Ready(context.Context, plugin.DetectionRequest) error {
	return d.readyErr
}

func (d *fakeModuleDetector) Applicable(_ context.Context, req plugin.DetectionRequest) (bool, error) {
	return req.PackageManager == model.PackageManagerNPM, nil
}

func (d *fakeModuleDetector) ResolveGraph(_ context.Context, req plugin.DetectionRequest) (plugin.DetectionResult, error) {
	return plugin.DetectionResult{DetectorName: "fake-detector", SubprojectInfo: req.Subproject}, nil
}

func (d *fakeModuleDetector) Install(context.Context, plugin.DetectionRequest) error {
	d.installed = true
	return nil
}

func TestServedDetectorModuleRoundTrip(t *testing.T) {
	constructed := 0
	fake := &fakeModuleDetector{}
	module := &plugin.DetectorModule{
		Descriptor: plugin.DetectorDescriptor{Name: "fake-detector"},
		Support:    []plugin.PackageManagerSupport{plugin.Support(model.PackageManagerNPM, "package-lock.json")},
		New: func(_ context.Context, host plugin.HostContext) (plugin.Detector, error) {
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
	descriptor, err := unmarshalBytes[plugin.DetectorDescriptor](out.Value)
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
	support, err := unmarshalBytes[[]plugin.PackageManagerSupport](supportOut.Value)
	if err != nil || len(*support) != 1 || (*support)[0].PackageManager != model.PackageManagerNPM {
		t.Fatalf("support round-trip mismatch: %+v err=%v", support, err)
	}
	if (*support)[0].EvidencePatterns[0] != "package-lock.json" {
		t.Fatalf("expected module support (not component support) to be served: %+v", *support)
	}
	if constructed != 0 {
		t.Fatalf("module-declared support must not construct the component, constructed=%d", constructed)
	}

	readyOut, err := server.DetectorReady(context.Background(), encodeRequest(t, &plugin.DetectRequest{}))
	if err != nil {
		t.Fatalf("DetectorReady: %v", err)
	}
	ready, err := unmarshalBytes[plugin.ReadyResponse](readyOut.Value)
	if err != nil || !ready.Ready || ready.Reason != "" {
		t.Fatalf("ready round-trip mismatch: %+v err=%v", ready, err)
	}
	if constructed != 1 {
		t.Fatalf("expected exactly one construction, got %d", constructed)
	}

	fake.readyErr = errors.New("node executable not found on PATH")
	readyOut, err = server.DetectorReady(context.Background(), encodeRequest(t, &plugin.DetectRequest{}))
	if err != nil {
		t.Fatalf("DetectorReady (not ready): %v", err)
	}
	ready, err = unmarshalBytes[plugin.ReadyResponse](readyOut.Value)
	if err != nil || ready.Ready || ready.Reason != "node executable not found on PATH" {
		t.Fatalf("not-ready mapping mismatch: %+v err=%v", ready, err)
	}

	applicableOut, err := server.DetectorApplicable(context.Background(), encodeRequest(t, &plugin.DetectRequest{PackageManager: model.PackageManagerNPM}))
	if err != nil {
		t.Fatalf("DetectorApplicable: %v", err)
	}
	applicable, err := unmarshalBytes[plugin.ApplicableResponse](applicableOut.Value)
	if err != nil || !applicable.Applicable {
		t.Fatalf("applicable round-trip mismatch: %+v err=%v", applicable, err)
	}

	detectOut, err := server.Detect(context.Background(), encodeRequest(t, &plugin.DetectRequest{PackageManager: model.PackageManagerNPM}))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	result, err := unmarshalBytes[plugin.DetectResponse](detectOut.Value)
	if err != nil || result.DetectorName != "fake-detector" {
		t.Fatalf("detect round-trip mismatch: %+v err=%v", result, err)
	}

	installOut, err := server.DetectorInstall(context.Background(), encodeRequest(t, &plugin.DetectRequest{}))
	if err != nil {
		t.Fatalf("DetectorInstall: %v", err)
	}
	install, err := unmarshalBytes[plugin.InstallResponse](installOut.Value)
	if err != nil || !install.Performed || !fake.installed {
		t.Fatalf("install round-trip mismatch: %+v installed=%v err=%v", install, fake.installed, err)
	}

	if constructed != 1 {
		t.Fatalf("expected the component to be constructed once, got %d", constructed)
	}
}

func TestServedDetectorModuleConstructionError(t *testing.T) {
	module := &plugin.DetectorModule{
		Descriptor: plugin.DetectorDescriptor{Name: "fake-detector"},
		New: func(context.Context, plugin.HostContext) (plugin.Detector, error) {
			return nil, errors.New("boom")
		},
	}
	server := &serviceServer{detector: newServedDetectorModule(module, fakeHostContext{})}
	if _, err := server.DetectorReady(context.Background(), encodeRequest(t, &plugin.DetectRequest{})); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected construction error, got %v", err)
	}
	if _, err := server.Detect(context.Background(), encodeRequest(t, &plugin.DetectRequest{})); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected construction error on Detect, got %v", err)
	}
}

// fakeModuleMatcher implements Matcher for the adapter mapping test.
type fakeModuleMatcher struct{}

func (fakeModuleMatcher) Descriptor() plugin.MatcherDescriptor {
	return plugin.MatcherDescriptor{Name: "fake-matcher"}
}

func (fakeModuleMatcher) Ready(context.Context, plugin.MatchRequest) error { return nil }

func (fakeModuleMatcher) Applicable(context.Context, plugin.MatchRequest) (bool, error) {
	return true, nil
}

func (fakeModuleMatcher) Match(context.Context, plugin.MatchRequest) (plugin.MatchResult, error) {
	return plugin.MatchResult{MatcherStats: plugin.MatcherStats{Name: "fake-matcher", MatchedPackages: 3}}, nil
}

func TestServedMatcherModuleRoundTrip(t *testing.T) {
	module := &plugin.MatcherModule{
		Descriptor: plugin.MatcherDescriptor{Name: "fake-matcher"},
		New: func(context.Context, plugin.HostContext) (plugin.Matcher, error) {
			return fakeModuleMatcher{}, nil
		},
	}
	server := &serviceServer{matcher: newServedMatcherModule(module, fakeHostContext{})}

	out, err := server.MatcherDescriptor(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("MatcherDescriptor: %v", err)
	}
	descriptor, err := unmarshalBytes[plugin.MatcherDescriptor](out.Value)
	if err != nil || descriptor.Name != "fake-matcher" {
		t.Fatalf("descriptor round-trip mismatch: %+v err=%v", descriptor, err)
	}

	readyOut, err := server.MatcherReady(context.Background(), encodeRequest(t, &plugin.MatchRequest{}))
	if err != nil {
		t.Fatalf("MatcherReady: %v", err)
	}
	ready, err := unmarshalBytes[plugin.ReadyResponse](readyOut.Value)
	if err != nil || !ready.Ready {
		t.Fatalf("ready round-trip mismatch: %+v err=%v", ready, err)
	}

	matchOut, err := server.Match(context.Background(), encodeRequest(t, &plugin.MatchRequest{}))
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	result, err := unmarshalBytes[plugin.MatchResponse](matchOut.Value)
	if err != nil || result.MatcherStats.MatchedPackages != 3 {
		t.Fatalf("match round-trip mismatch: %+v err=%v", result, err)
	}
}
