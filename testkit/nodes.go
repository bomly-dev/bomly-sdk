package testkit

import (
	"testing"

	sdk "github.com/bomly-dev/bomly-sdk"
)

// MustDependencyNode constructs a dependency node from a raw package URL and
// fails the test when the constructor rejects it. Test-fixture counterpart of
// sdk.NewDependencyNodeFromPURL for detector, matcher, and plugin tests.
func MustDependencyNode(t testing.TB, rawPURL string) *sdk.DependencyNode {
	t.Helper()
	node, err := sdk.NewDependencyNodeFromPURL(rawPURL)
	if err != nil {
		t.Fatalf("NewDependencyNodeFromPURL(%q): %v", rawPURL, err)
	}
	return node
}

// MustDependencyCoords constructs a dependency node from coordinates and
// fails the test when the constructor rejects them. Test-fixture counterpart
// of sdk.NewDependencyNode.
func MustDependencyCoords(t testing.TB, coords sdk.Coordinates) *sdk.DependencyNode {
	t.Helper()
	node, err := sdk.NewDependencyNode(coords)
	if err != nil {
		t.Fatalf("NewDependencyNode(%+v): %v", coords, err)
	}
	return node
}

// MustModuleNode constructs a module node and fails the test when the
// constructor rejects the path or coordinates. Test-fixture counterpart of
// sdk.NewModuleNode.
func MustModuleNode(t testing.TB, manifestPath string, coords sdk.Coordinates) *sdk.ModuleNode {
	t.Helper()
	node, err := sdk.NewModuleNode(manifestPath, coords)
	if err != nil {
		t.Fatalf("NewModuleNode(%q, %+v): %v", manifestPath, coords, err)
	}
	return node
}
