package sdk

import "testing"

func TestRelationshipForPathHonorsUnknownTarget(t *testing.T) {
	// The application root is a module node under the union; paths are
	// heterogeneous GraphNode slices now.
	root := mustModule(t, "package.json", Coordinates{Name: "root", Type: PackageTypeApplication})
	orphan := mustDep(t, Coordinates{Name: "orphan"})
	orphan.Relationship = DependencyRelationshipUnknown
	if got := RelationshipForPath([]GraphNode{root, orphan}); got != DependencyRelationshipUnknown {
		t.Fatalf("RelationshipForPath() = %q, want unknown", got)
	}
}

func TestRelationshipForPathDerivesDirectAndTransitive(t *testing.T) {
	nodes := []GraphNode{
		mustModule(t, "package.json", Coordinates{Name: "root"}),
		mustDep(t, Coordinates{Name: "parent", Version: "1"}),
		mustDep(t, Coordinates{Name: "child", Version: "1"}),
	}
	if got := RelationshipForPath(nodes[:2]); got != DependencyRelationshipDirect {
		t.Fatalf("direct relationship = %q", got)
	}
	if got := RelationshipForPath(nodes); got != DependencyRelationshipTransitive {
		t.Fatalf("transitive relationship = %q", got)
	}
}

func TestMergeDependencyRelationshipUsesBestKnownRelationship(t *testing.T) {
	got := MergeDependencyRelationship(DependencyRelationshipUnknown, DependencyRelationshipTransitive)
	got = MergeDependencyRelationship(got, DependencyRelationshipDirect)
	if got != DependencyRelationshipDirect {
		t.Fatalf("merged relationship = %q, want direct", got)
	}
}
