package sdk

import "testing"

// mustDepPURL constructs a dependency node from a raw package URL, failing
// the test on constructor error.
func mustDepPURL(t testing.TB, raw string) *DependencyNode {
	t.Helper()
	node, err := NewDependencyNodeFromPURL(raw)
	if err != nil {
		t.Fatalf("NewDependencyNodeFromPURL(%q): %v", raw, err)
	}
	return node
}

// mustDep constructs a dependency node from coordinates, failing the test
// on constructor error.
func mustDep(t testing.TB, coords Coordinates) *DependencyNode {
	t.Helper()
	node, err := NewDependencyNode(coords)
	if err != nil {
		t.Fatalf("NewDependencyNode(%+v): %v", coords, err)
	}
	return node
}

// mustModule constructs a module node, failing the test on constructor error.
func mustModule(t testing.TB, manifestPath string, coords Coordinates) *ModuleNode {
	t.Helper()
	node, err := NewModuleNode(manifestPath, coords)
	if err != nil {
		t.Fatalf("NewModuleNode(%q, %+v): %v", manifestPath, coords, err)
	}
	return node
}

// mustManifest constructs a manifest node, failing the test on constructor
// error.
func mustManifest(t testing.TB, path string) *ManifestNode {
	t.Helper()
	node, err := NewManifestNode(path, "")
	if err != nil {
		t.Fatalf("NewManifestNode(%q): %v", path, err)
	}
	return node
}
