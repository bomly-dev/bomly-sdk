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

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

// --- fake detector module ---------------------------------------------------

type fakeDetector struct {
	plugin.BaseDetector
}

func (fakeDetector) Descriptor() plugin.DetectorDescriptor {
	return plugin.DetectorDescriptor{Name: "conformance-fake-detector", Version: "0.0.1"}
}

func (fakeDetector) PackageManagerSupport() []plugin.PackageManagerSupport {
	return []plugin.PackageManagerSupport{plugin.Support(model.PackageManagerNPM, "package-lock.json")}
}

func (fakeDetector) ResolveGraph(context.Context, plugin.DetectionRequest) (plugin.DetectionResult, error) {
	return plugin.DetectionResult{}, nil
}

func fakeDetectorModule() plugin.Module {
	return plugin.Module{
		Kind: plugin.PluginKindDetector,
		Detector: &plugin.DetectorModule{
			Descriptor: plugin.DetectorDescriptor{Name: "conformance-fake-detector", Version: "0.0.1"},
			Support:    []plugin.PackageManagerSupport{plugin.Support(model.PackageManagerNPM, "package-lock.json")},
			New: func(context.Context, plugin.HostContext) (plugin.Detector, error) {
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
	plugin.BaseMatcher
	config fakeMatcherConfig
}

func fakeMatcherDescriptor() plugin.MatcherDescriptor {
	return plugin.MatcherDescriptor{
		Name:         "conformance-fake-matcher",
		Version:      "0.0.1",
		Capabilities: []string{plugin.CapabilityPackageUpdates},
		ConfigSchema: plugin.MustConfigSchemaFor(fakeMatcherConfig{}),
	}
}

func (m fakeMatcher) Descriptor() plugin.MatcherDescriptor { return fakeMatcherDescriptor() }

func (m fakeMatcher) Match(_ context.Context, req plugin.MatchRequest) (plugin.MatchResult, error) {
	if req.AcceptPackageUpdates {
		var updates []*model.Package
		if req.Registry != nil {
			for _, pkg := range req.Registry.All() {
				update := &model.Package{Coordinates: model.Coordinates{PURL: pkg.PURL}}
				update.Metadata = map[string]any{"conformance.annotation": m.config.Annotation}
				updates = append(updates, update)
			}
		}
		return plugin.MatchResult{PackageUpdates: updates}, nil
	}
	return plugin.MatchResult{Registry: req.Registry}, nil
}

func fakeMatcherModule() plugin.Module {
	return plugin.Module{
		Kind: plugin.PluginKindMatcher,
		Matcher: &plugin.MatcherModule{
			Descriptor: fakeMatcherDescriptor(),
			New: func(_ context.Context, host plugin.HostContext) (plugin.Matcher, error) {
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
}`, plugin.PackageManifestSchemaVersion, plugin.RuntimeHashiCorpGRPC, plugin.PluginAPIVersion, runtime.GOOS, runtime.GOARCH)
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
	matcher := component.(plugin.Matcher)

	registry := model.NewPackageRegistry()
	registry.Ensure("pkg:npm/left-pad@1.3.0")
	result, err := matcher.Match(context.Background(), plugin.MatchRequest{
		Registry:             registry,
		AcceptPackageUpdates: true,
	})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(result.PackageUpdates) != 1 {
		t.Fatalf("expected 1 package update, got %d", len(result.PackageUpdates))
	}
	merged := model.ApplyPackageUpdates(registry, result.PackageUpdates)
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

	"github.com/bomly-dev/bomly-sdk/plugin"
	"github.com/bomly-dev/bomly-sdk/runtime"
)

type config struct {
	Annotation string ` + "`" + `json:"annotation" doc:"Annotation added to matched packages" default:"conformance"` + "`" + `
}

type matcher struct {
	plugin.BaseMatcher
	config config
}

func descriptor() plugin.MatcherDescriptor {
	return plugin.MatcherDescriptor{
		Name:         "conformance-fake-matcher",
		Version:      "0.0.1",
		Capabilities: []string{plugin.CapabilityPackageUpdates},
		ConfigSchema: plugin.MustConfigSchemaFor(config{}),
	}
}

func (m matcher) Descriptor() plugin.MatcherDescriptor { return descriptor() }

func (m matcher) Match(_ context.Context, req plugin.MatchRequest) (plugin.MatchResult, error) {
	return plugin.MatchResult{Registry: req.Registry}, nil
}

func main() {
	runtime.ServeModule(plugin.Module{
		Kind: plugin.PluginKindMatcher,
		Matcher: &plugin.MatcherModule{
			Descriptor: descriptor(),
			New: func(_ context.Context, host plugin.HostContext) (plugin.Matcher, error) {
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
	// tidy already resolved every dependency, so a build failure here is a
	// compile error in the fixture (or the contract it is written against),
	// not a missing module cache: fail, do not skip, or a broken fixture
	// passes silently.
	build := exec.CommandContext(ctx, goBinary, "build", "-o", binaryPath, ".")
	build.Dir = fixtureDir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fixture binary: %v\n%s", err, out)
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
