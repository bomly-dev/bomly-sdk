package model

import "testing"

// Shared fixture constructors for the root test suite. They fail the test
// on constructor error so a case reads as the graph it builds, not as error
// plumbing.

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

func idsOf(nodes []GraphNode) []string {
	ids := make([]string, 0, len(nodes))
	for _, n := range nodes {
		ids = append(ids, n.NodeID())
	}
	return ids
}

// workspaceNode is the case per-site attribution exists for: one package
// version used two ways. In "apps/web" it is a direct development dependency;
// in "apps/api" it is a transitive runtime dependency.
func workspaceNode(t *testing.T) *DependencyNode {
	t.Helper()
	node, err := NewDependencyNode(Coordinates{Name: "left-pad", Version: "1.3.0", Ecosystem: EcosystemNPM})
	if err != nil {
		t.Fatalf("NewDependencyNode: %v", err)
	}
	node.Locations = []PackageLocation{
		{
			RealPath:     "apps/web/package.json",
			ModuleRoot:   "apps/web",
			Scopes:       []Scope{ScopeDevelopment},
			Relationship: DependencyRelationshipDirect,
		},
		{
			RealPath:     "apps/api/package-lock.json",
			ModuleRoot:   "apps/api",
			Scopes:       []Scope{ScopeRuntime},
			Relationship: DependencyRelationshipTransitive,
		},
	}
	return node
}
