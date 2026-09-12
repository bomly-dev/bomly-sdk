package sdk

import "testing"

// The same name and version in two ecosystems are two packages, and the merged
// graph has to hold both. ADR-0041 makes the canonical package URL the
// identity precisely so this is decided by construction rather than by
// whichever fold happened to run: pkg:npm/left-pad@1.0.0 and
// pkg:pypi/left-pad@1.0.0 are different strings, so they are different nodes.
//
// The failure this rules out is silent. A key of name+version -- the shape
// every hand-written index reaches for first -- collapses the two, and the
// survivor inherits the loser's findings, licenses and locations. Nothing
// errors; one package simply wears another's vulnerabilities.
//
// It is pinned here rather than in a consumer because identity is the SDK's
// (ADR-0040), and because a consumer's version of this test passes for its own
// reasons -- its pipeline may never put both ecosystems in one graph.
func TestSameNameInTwoEcosystemsStaysTwoNodes(t *testing.T) {
	const (
		name    = "left-pad"
		version = "1.0.0"
	)

	graph := New()
	ids := make(map[Ecosystem]string)
	for _, ecosystem := range []Ecosystem{EcosystemNPM, EcosystemPython} {
		node, err := NewDependencyNode(Coordinates{Ecosystem: ecosystem, Name: name, Version: version})
		if err != nil {
			t.Fatalf("new %s node: %v", ecosystem, err)
		}
		if _, err := graph.InsertNode(node); err != nil {
			t.Fatalf("insert %s node: %v", ecosystem, err)
		}
		ids[ecosystem] = node.NodeID()
	}

	// Stated as the identities themselves, not as a count, so a failure says
	// which two collapsed rather than that some number moved.
	if ids[EcosystemNPM] == ids[EcosystemPython] {
		t.Fatalf("%s and %s in %s@%s share the identity %q; one package now carries the other's findings",
			EcosystemNPM, EcosystemPython, name, version, ids[EcosystemNPM])
	}
	if got, want := ids[EcosystemNPM], "pkg:npm/"+name+"@"+version; got != want {
		t.Errorf("npm identity = %q, want %q", got, want)
	}
	if got, want := ids[EcosystemPython], "pkg:pypi/"+name+"@"+version; got != want {
		t.Errorf("python identity = %q, want %q", got, want)
	}

	nodes := graph.DependencyNodes()
	if len(nodes) != 2 {
		t.Fatalf("merged graph holds %d dependency nodes, want 2: the insert folded two packages into one", len(nodes))
	}
	// Insertion folds by identity, so re-inserting must not add a third. The
	// same mechanism that keeps these two apart has to keep a repeat together.
	repeat, err := NewDependencyNode(Coordinates{Ecosystem: EcosystemNPM, Name: name, Version: version})
	if err != nil {
		t.Fatalf("new repeat node: %v", err)
	}
	if _, err := graph.InsertNode(repeat); err != nil {
		t.Fatalf("insert repeat node: %v", err)
	}
	if got := len(graph.DependencyNodes()); got != 2 {
		t.Errorf("re-inserting %s %s@%s made %d nodes, want 2; identity is not folding", EcosystemNPM, name, version, got)
	}
}
