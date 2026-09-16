package testkit

import (
	"testing"

	"github.com/bomly-dev/bomly-sdk/model"
)

// MustDependencyNode constructs a dependency node from a raw package URL and
// fails the test when the constructor rejects it. Test-fixture counterpart of
// model.NewDependencyNodeFromPURL for detector, matcher, and plugin tests.
func MustDependencyNode(t testing.TB, rawPURL string) *model.DependencyNode {
	t.Helper()
	node, err := model.NewDependencyNodeFromPURL(rawPURL)
	if err != nil {
		t.Fatalf("NewDependencyNodeFromPURL(%q): %v", rawPURL, err)
	}
	return node
}

// MustDependencyCoords constructs a dependency node from coordinates and
// fails the test when the constructor rejects them. Test-fixture counterpart
// of model.NewDependencyNode.
func MustDependencyCoords(t testing.TB, coords model.Coordinates) *model.DependencyNode {
	t.Helper()
	node, err := model.NewDependencyNode(coords)
	if err != nil {
		t.Fatalf("NewDependencyNode(%+v): %v", coords, err)
	}
	return node
}

// MustModuleNode constructs a module node and fails the test when the
// constructor rejects the path or coordinates. Test-fixture counterpart of
// model.NewModuleNode.
func MustModuleNode(t testing.TB, manifestPath string, coords model.Coordinates) *model.ModuleNode {
	t.Helper()
	node, err := model.NewModuleNode(manifestPath, coords)
	if err != nil {
		t.Fatalf("NewModuleNode(%q, %+v): %v", manifestPath, coords, err)
	}
	return node
}
