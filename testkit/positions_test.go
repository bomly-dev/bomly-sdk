package testkit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

// fakeLockfileDetector is a minimal plugin.Detector that parses "fake.lock"
// (one "name version" pair per line) and records the declaring line as the
// package's source position.
type fakeLockfileDetector struct{}

func (fakeLockfileDetector) Descriptor() plugin.DetectorDescriptor {
	return plugin.DetectorDescriptor{Name: "fake-lockfile"}
}

func (fakeLockfileDetector) PackageManagerSupport() []plugin.PackageManagerSupport {
	return []plugin.PackageManagerSupport{plugin.Support(model.PackageManager("fake"), "fake.lock")}
}

func (fakeLockfileDetector) Ready(context.Context, plugin.DetectionRequest) error { return nil }

func (fakeLockfileDetector) Applicable(context.Context, plugin.DetectionRequest) (bool, error) {
	return true, nil
}

func (fakeLockfileDetector) ResolveGraph(_ context.Context, req plugin.DetectionRequest) (plugin.DetectionResult, error) {
	graph := model.New()
	positions := map[string][]*model.SourcePosition{}
	line := 0
	data, err := os.ReadFile(filepath.Join(req.ProjectPath, "fake.lock"))
	if err != nil {
		return plugin.DetectionResult{}, err
	}
	for raw := range strings.SplitSeq(string(data), "\n") {
		line++
		fields := strings.Fields(raw)
		if len(fields) != 2 {
			continue
		}
		name, version := fields[0], fields[1]
		dep, err := model.NewDependencyNode(model.Coordinates{
			Name: name, Version: version, Ecosystem: "fake",
		})
		if err != nil {
			return plugin.DetectionResult{}, err
		}
		if err := graph.AddNode(dep); err != nil {
			return plugin.DetectionResult{}, err
		}
		if name != "positionless" {
			positions[dep.NodeID()] = []*model.SourcePosition{{File: "fake.lock", Line: line}}
		}
	}
	for key, entries := range positions {
		if node, ok := graph.DependencyNode(key); ok {
			for _, pos := range entries {
				node.Locations = append(node.Locations, model.PackageLocation{
					RealPath: pos.File, AccessPath: pos.File, Position: pos,
				})
			}
		}
	}
	return plugin.DetectionResult{
		Graphs: model.SingleGraphContainer(graph, model.ManifestMetadata{Path: "fake.lock"}),
	}, nil
}

func TestRequireLockfilePositionsPassesForPositionedPackages(t *testing.T) {
	dir := t.TempDir()
	lock := "foo 1.0.0\nbar 2.0.0\npositionless 3.0.0\n"
	if err := os.WriteFile(filepath.Join(dir, "fake.lock"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}

	// Node IDs are canonical package URLs now.
	RequireLockfilePositions(t, fakeLockfileDetector{}, dir, []string{"pkg:fake/foo@1.0.0", "pkg:fake/bar@2.0.0"})
}

func TestRequireLockfilePositionsDetectsMissingPositions(t *testing.T) {
	dir := t.TempDir()
	lock := "foo 1.0.0\npositionless 3.0.0\n"
	if err := os.WriteFile(filepath.Join(dir, "fake.lock"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}

	detector := fakeLockfileDetector{}
	result, err := detector.ResolveGraph(context.Background(), plugin.DetectionRequest{ProjectPath: dir})
	if err != nil {
		t.Fatal(err)
	}
	graph, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatal(err)
	}

	positioned, ok := graph.Node("pkg:fake/foo@1.0.0")
	if !ok || !hasSourcePosition(positioned) {
		t.Fatalf("expected pkg:fake/foo@1.0.0 to carry a source position, got %#v", positioned)
	}
	bare, ok := graph.Node("pkg:fake/positionless@3.0.0")
	if !ok {
		t.Fatal("expected pkg:fake/positionless@3.0.0 in graph")
	}
	if hasSourcePosition(bare) {
		t.Fatalf("expected pkg:fake/positionless@3.0.0 to have no source position, got %#v", bare.NodeLocations())
	}
}
