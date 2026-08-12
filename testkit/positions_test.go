package testkit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/bomly-dev/bomly-sdk"
)

// fakeLockfileDetector is a minimal sdk.Detector that parses "fake.lock"
// (one "name version" pair per line) and records the declaring line as the
// package's source position.
type fakeLockfileDetector struct{}

func (fakeLockfileDetector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{Name: "fake-lockfile"}
}

func (fakeLockfileDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManager("fake"), "fake.lock")}
}

func (fakeLockfileDetector) Ready(context.Context, sdk.DetectionRequest) error { return nil }

func (fakeLockfileDetector) Applicable(context.Context, sdk.DetectionRequest) (bool, error) {
	return true, nil
}

func (fakeLockfileDetector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	graph := sdk.New()
	positions := map[string][]*sdk.SourcePosition{}
	line := 0
	data, err := os.ReadFile(filepath.Join(req.ProjectPath, "fake.lock"))
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line++
		fields := strings.Fields(raw)
		if len(fields) != 2 {
			continue
		}
		name, version := fields[0], fields[1]
		dep := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{
			Name: name, Version: version, Ecosystem: "fake",
		}})
		if err := graph.AddNode(dep); err != nil {
			return sdk.DetectionResult{}, err
		}
		if name != "positionless" {
			positions[name+"@"+version] = []*sdk.SourcePosition{{File: "fake.lock", Line: line}}
		}
	}
	for key, entries := range positions {
		if node, ok := graph.Node(key); ok {
			for _, pos := range entries {
				node.Locations = append(node.Locations, sdk.PackageLocation{
					RealPath: pos.File, AccessPath: pos.File, Position: pos,
				})
			}
		}
	}
	return sdk.DetectionResult{
		Graphs: sdk.SingleGraphContainer(graph, sdk.ManifestMetadata{Path: "fake.lock"}),
	}, nil
}

func TestRequireLockfilePositionsPassesForPositionedPackages(t *testing.T) {
	dir := t.TempDir()
	lock := "foo 1.0.0\nbar 2.0.0\npositionless 3.0.0\n"
	if err := os.WriteFile(filepath.Join(dir, "fake.lock"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}

	RequireLockfilePositions(t, fakeLockfileDetector{}, dir, []string{"foo@1.0.0", "bar@2.0.0"})
}

func TestRequireLockfilePositionsDetectsMissingPositions(t *testing.T) {
	dir := t.TempDir()
	lock := "foo 1.0.0\npositionless 3.0.0\n"
	if err := os.WriteFile(filepath.Join(dir, "fake.lock"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}

	detector := fakeLockfileDetector{}
	result, err := detector.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: dir})
	if err != nil {
		t.Fatal(err)
	}
	graph, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatal(err)
	}

	positioned, ok := graph.Node("foo@1.0.0")
	if !ok || !hasSourcePosition(positioned) {
		t.Fatalf("expected foo@1.0.0 to carry a source position, got %#v", positioned)
	}
	bare, ok := graph.Node("positionless@3.0.0")
	if !ok {
		t.Fatal("expected positionless@3.0.0 in graph")
	}
	if hasSourcePosition(bare) {
		t.Fatalf("expected positionless@3.0.0 to have no source position, got %#v", bare.Locations)
	}
}
