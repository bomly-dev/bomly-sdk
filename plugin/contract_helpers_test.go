package plugin

import (
	"testing"

	"github.com/bomly-dev/bomly-sdk/model"
)

// mustDependency builds a dependency node for a contract-side fixture, failing
// the test on constructor error.
func mustDependency(t testing.TB, coords model.Coordinates) *model.DependencyNode {
	t.Helper()
	node, err := model.NewDependencyNode(coords)
	if err != nil {
		t.Fatalf("NewDependencyNode(%+v): %v", coords, err)
	}
	return node
}
