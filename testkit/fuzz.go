// Package testkit provides test helpers for component modules and external
// plugins: fuzz-target invariants, Go binary builders for fake tools, and
// lockfile position assertions.
package testkit

import (
	"testing"

	"github.com/bomly-dev/bomly-sdk/model"
)

// MaxFuzzInputSize is the shared upper bound for parser fuzz payloads.
const MaxFuzzInputSize = 1 << 20

// RequireFuzzGraphValid verifies the minimum invariants of a successfully
// parsed dependency graph.
func RequireFuzzGraphValid(t *testing.T, graph *model.Graph) {
	t.Helper()
	if graph == nil {
		t.Fatal("successful parse returned nil graph")
	}
	graph.WalkNodes(func(node model.GraphNode) bool {
		if node == nil {
			t.Fatal("graph contains nil node")
		}
		if node.NodeID() == "" {
			t.Fatalf("graph contains node with empty ID: %+v", node)
		}
		return true
	})
	graph.WalkEdges(func(from, to model.GraphNode) bool {
		if from == nil || to == nil {
			t.Fatalf("graph contains nil edge endpoint: from=%+v to=%+v", from, to)
		}
		if from.NodeID() == "" || to.NodeID() == "" {
			t.Fatalf("graph contains edge with empty endpoint ID: from=%+v to=%+v", from, to)
		}
		return true
	})
}
