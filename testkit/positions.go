package testkit

import (
	"context"
	"strings"
	"testing"

	sdk "github.com/bomly-dev/bomly-sdk"
)

// RequireLockfilePositions resolves fixtureDir with the given detector and
// asserts that every named package in the resolved graph carries at least one
// non-empty source position (a location whose Position names a file and a
// 1-based line). It is the per-detector replacement for the Bomly CLI's
// cross-detector position test: each detector module keeps its own lockfile
// fixture and asserts its own position extraction with one call.
//
// wantPositionKeys entries are graph node IDs — canonical package URLs such
// as "pkg:npm/left-pad@1.3.0" (ADR-0041). A missing node or a node without a
// position fails the test with the offending key.
func RequireLockfilePositions(t *testing.T, detector sdk.Detector, fixtureDir string, wantPositionKeys []string) {
	t.Helper()
	if detector == nil {
		t.Fatal("RequireLockfilePositions: detector is nil")
	}
	if strings.TrimSpace(fixtureDir) == "" {
		t.Fatal("RequireLockfilePositions: fixtureDir is empty")
	}
	if len(wantPositionKeys) == 0 {
		t.Fatal("RequireLockfilePositions: wantPositionKeys is empty")
	}

	request := sdk.DetectionRequest{
		ProjectPath: fixtureDir,
		ExecutionTarget: sdk.ExecutionTarget{
			Kind:     sdk.ExecutionTargetFilesystem,
			Location: fixtureDir,
		},
	}
	request.Subproject.ExecutionTarget = request.ExecutionTarget

	result, err := detector.ResolveGraph(context.Background(), request)
	if err != nil {
		t.Fatalf("RequireLockfilePositions: ResolveGraph(%q): %v", fixtureDir, err)
	}
	graph, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("RequireLockfilePositions: consolidate detection graphs: %v", err)
	}
	if graph == nil {
		t.Fatal("RequireLockfilePositions: detector produced no graph")
	}

	for _, key := range wantPositionKeys {
		node, ok := graph.Node(key)
		if !ok || node == nil {
			t.Errorf("package %q missing from resolved graph", key)
			continue
		}
		if !hasSourcePosition(node) {
			t.Errorf("package %q has no source position; locations = %#v", key, node.NodeLocations())
		}
	}
}

// hasSourcePosition reports whether at least one location on the node carries
// a position with a file and a 1-based line.
func hasSourcePosition(node sdk.GraphNode) bool {
	for _, location := range node.NodeLocations() {
		position := location.Position
		if position != nil && strings.TrimSpace(position.File) != "" && position.Line >= 1 {
			return true
		}
	}
	return false
}
