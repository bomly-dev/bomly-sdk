package conformance

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	sdk "github.com/bomly-dev/bomly-sdk"
)

// --- fake detector module ---------------------------------------------------

type fakeDetector struct {
	sdk.BaseDetector
}

func (fakeDetector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{Name: "conformance-fake-detector"}
}

func (fakeDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerNPM, "package-lock.json")}
}

func (fakeDetector) ResolveGraph(context.Context, sdk.DetectionRequest) (sdk.DetectionResult, error) {
	return sdk.DetectionResult{}, nil
}

func fakeDetectorModule() sdk.Module {
	return sdk.Module{
		Kind: sdk.PluginKindDetector,
		Detector: &sdk.DetectorModule{
			Descriptor: sdk.DetectorDescriptor{Name: "conformance-fake-detector"},
			Support:    []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerNPM, "package-lock.json")},
			New: func(context.Context, sdk.HostContext) (sdk.Detector, error) {
				return fakeDetector{}, nil
			},
		},
	}
}

// --- fake matcher module with the package-updates capability ----------------

type fakeMatcherConfig struct {
	Annotation string `json:"annotation" doc:"Annotation added to matched packages" default:"conformance"`
}

type fakeMatcher struct {
	sdk.BaseMatcher
	config fakeMatcherConfig
}

func fakeMatcherDescriptor() sdk.MatcherDescriptor {
	return sdk.MatcherDescriptor{
		Name:         "conformance-fake-matcher",
		Capabilities: []string{sdk.CapabilityPackageUpdates},
		ConfigSchema: sdk.MustConfigSchemaFor(fakeMatcherConfig{}),
	}
}

func (m fakeMatcher) Descriptor() sdk.MatcherDescriptor { return fakeMatcherDescriptor() }

func (m fakeMatcher) Match(_ context.Context, req sdk.MatchRequest) (sdk.MatchResult, error) {
	if req.AcceptPackageUpdates {
		var updates []*sdk.Package
		if req.Registry != nil {
			for _, pkg := range req.Registry.All() {
				update := &sdk.Package{Coordinates: sdk.Coordinates{PURL: pkg.PURL}}
				update.Metadata = map[string]any{"conformance.annotation": m.config.Annotation}
				updates = append(updates, update)
			}
		}
		return sdk.MatchResult{PackageUpdates: updates}, nil
	}
	return sdk.MatchResult{Registry: req.Registry}, nil
}

func fakeMatcherModule() sdk.Module {
	return sdk.Module{
		Kind: sdk.PluginKindMatcher,
		Matcher: &sdk.MatcherModule{
			Descriptor: fakeMatcherDescriptor(),
			New: func(_ context.Context, host sdk.HostContext) (sdk.Matcher, error) {
				matcher := fakeMatcher{}
				if err := host.DecodeConfig(&matcher.config); err != nil {
					return nil, fmt.Errorf("decode config: %w", err)
				}
				return matcher, nil
			},
		},
	}
}

// --- suite self-tests -------------------------------------------------------

func TestSuiteAgainstFakeDetector(t *testing.T) {
	Test(t, Config{Module: fakeDetectorModule()})
}

func TestSuiteAgainstFakeMatcher(t *testing.T) {
	manifestPath := filepath.Join(t.TempDir(), "bomly-plugin.json")
	manifest := fmt.Sprintf(`{
  "schemaVersion": %q,
  "id": "conformance-fake-matcher",
  "name": "Conformance Fake Matcher",
  "version": "0.0.1",
  "kind": "matcher",
  "runtime": %q,
  "pluginApiVersion": %q,
  "entrypoint": {"%s/%s": "bin/conformance-fake-matcher"}
}`, sdk.PackageManifestSchemaVersion, sdk.RuntimeHashiCorpGRPC, sdk.PluginAPIVersion, runtime.GOOS, runtime.GOARCH)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest fixture: %v", err)
	}

	Test(t, Config{
		Module:       fakeMatcherModule(),
		ManifestPath: manifestPath,
		SampleConfig: []byte(`{"annotation":"from-sample-config"}`),
	})
}

func TestSuiteMatcherPackageUpdatesMerge(t *testing.T) {
	host := newStubHostContext([]byte(`{"annotation":"merge-check"}`))
	component, err := constructComponent(context.Background(), fakeMatcherModule(), host)
	if err != nil {
		t.Fatalf("construct matcher: %v", err)
	}
	matcher := component.(sdk.Matcher)

	registry := sdk.NewPackageRegistry()
	registry.Ensure("pkg:npm/left-pad@1.3.0")
	result, err := matcher.Match(context.Background(), sdk.MatchRequest{
		Registry:             registry,
		AcceptPackageUpdates: true,
	})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(result.PackageUpdates) != 1 {
		t.Fatalf("expected 1 package update, got %d", len(result.PackageUpdates))
	}
	merged := sdk.ApplyPackageUpdates(registry, result.PackageUpdates)
	pkg, ok := merged.Get("pkg:npm/left-pad@1.3.0")
	if !ok {
		t.Fatal("merged registry lost the package")
	}
	if pkg.Metadata["conformance.annotation"] != "merge-check" {
		t.Fatalf("expected the sample-config annotation on the merged package, got %v", pkg.Metadata["conformance.annotation"])
	}
}

// --- managed transport probe against a real fixture binary ------------------

// TestProbeBinaryAgainstFixture builds a real plugin binary that serves the
// fake matcher module via ServeModule and probes it over the managed
// transport.
func TestProbeBinaryAgainstFixture(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go binary not on PATH; skipping fixture binary probe")
	}

	sdkRoot := sdkModuleRoot(t)
	fixtureDir := t.TempDir()

	goMod := fmt.Sprintf(`module conformancefixture

go 1.26.3

require github.com/bomly-dev/bomly-sdk v0.0.0

replace github.com/bomly-dev/bomly-sdk => %s
`, sdkRoot)
	if err := os.WriteFile(filepath.Join(fixtureDir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("write fixture go.mod: %v", err)
	}
	// Reuse the SDK's go.sum so the fixture build resolves the SDK's
	// dependency graph from the local module cache without extra verification
	// round trips.
	sum, err := os.ReadFile(filepath.Join(sdkRoot, "go.sum"))
	if err != nil {
		t.Fatalf("read sdk go.sum: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fixtureDir, "go.sum"), sum, 0o644); err != nil {
		t.Fatalf("write fixture go.sum: %v", err)
	}

	mainGo := `package main

import (
	"context"
	"fmt"

	sdk "github.com/bomly-dev/bomly-sdk"
)

type config struct {
	Annotation string ` + "`" + `json:"annotation" doc:"Annotation added to matched packages" default:"conformance"` + "`" + `
}

type matcher struct {
	sdk.BaseMatcher
	config config
}

func descriptor() sdk.MatcherDescriptor {
	return sdk.MatcherDescriptor{
		Name:         "conformance-fake-matcher",
		Capabilities: []string{sdk.CapabilityPackageUpdates},
		ConfigSchema: sdk.MustConfigSchemaFor(config{}),
	}
}

func (m matcher) Descriptor() sdk.MatcherDescriptor { return descriptor() }

func (m matcher) Match(_ context.Context, req sdk.MatchRequest) (sdk.MatchResult, error) {
	return sdk.MatchResult{Registry: req.Registry}, nil
}

func main() {
	sdk.ServeModule(sdk.Module{
		Kind: sdk.PluginKindMatcher,
		Matcher: &sdk.MatcherModule{
			Descriptor: descriptor(),
			New: func(_ context.Context, host sdk.HostContext) (sdk.Matcher, error) {
				m := matcher{}
				if err := host.DecodeConfig(&m.config); err != nil {
					return nil, fmt.Errorf("decode config: %w", err)
				}
				return m, nil
			},
		},
	})
}
`
	if err := os.WriteFile(filepath.Join(fixtureDir, "main.go"), []byte(mainGo), 0o644); err != nil {
		t.Fatalf("write fixture main.go: %v", err)
	}

	binaryPath := filepath.Join(fixtureDir, "conformance-fixture")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	tidy := exec.CommandContext(ctx, goBinary, "mod", "tidy")
	tidy.Dir = fixtureDir
	if out, err := tidy.CombinedOutput(); err != nil {
		t.Skipf("cannot tidy fixture module (offline module cache incomplete?): %v\n%s", err, out)
	}
	build := exec.CommandContext(ctx, goBinary, "build", "-o", binaryPath, ".")
	build.Dir = fixtureDir
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("cannot build fixture binary (offline module cache incomplete?): %v\n%s", err, out)
	}

	ProbeBinary(t, binaryPath)
	ProbeBinary(t, binaryPath, WithModule(fakeMatcherModule()))
}

// sdkModuleRoot resolves the SDK checkout root from this file's location.
func sdkModuleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve caller path")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(file), ".."))
	if err != nil {
		t.Fatalf("resolve sdk root: %v", err)
	}
	return root
}
