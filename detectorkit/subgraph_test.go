package detectorkit

import (
	"testing"

	sdk "github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/testkit"
)

// Node IDs are canonical package URLs now: pkg:generic/<name>.
func subgraphFixture(t *testing.T, edges [][2]string) *sdk.Graph {
	t.Helper()
	g := sdk.New()
	added := map[string]struct{}{}
	addNode := func(id string) {
		if _, ok := added[id]; ok {
			return
		}
		added[id] = struct{}{}
		if err := g.AddNode(testkit.MustDependencyNode(t, id)); err != nil {
			t.Fatalf("add node %q: %v", id, err)
		}
	}
	for _, edge := range edges {
		addNode(edge[0])
		addNode(edge[1])
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("add edge %v: %v", edge, err)
		}
	}
	return g
}

func TestSubgraphFromExtractsReachableSubtree(t *testing.T) {
	g := subgraphFixture(t, [][2]string{
		{"pkg:generic/root", "pkg:generic/a"}, {"pkg:generic/a", "pkg:generic/shared"},
		{"pkg:generic/module", "pkg:generic/b"}, {"pkg:generic/b", "pkg:generic/shared"}, // diamond: shared reachable twice
		{"pkg:generic/unrelated", "pkg:generic/c"},
	})

	sub, err := SubgraphFrom(g, "pkg:generic/module")
	if err != nil {
		t.Fatalf("SubgraphFrom() error = %v", err)
	}
	for _, want := range []string{"pkg:generic/module", "pkg:generic/b", "pkg:generic/shared"} {
		if _, ok := sub.Node(want); !ok {
			t.Fatalf("expected node %q in subgraph", want)
		}
	}
	for _, forbidden := range []string{"pkg:generic/root", "pkg:generic/a", "pkg:generic/unrelated", "pkg:generic/c"} {
		if _, ok := sub.Node(forbidden); ok {
			t.Fatalf("unexpected node %q in subgraph", forbidden)
		}
	}
	if sub.Size() != 3 {
		t.Fatalf("expected 3 nodes, got %d", sub.Size())
	}
	deps, err := sub.DirectDependencies("pkg:generic/b")
	if err != nil || len(deps) != 1 || deps[0].NodeID() != "pkg:generic/shared" {
		t.Fatalf("expected b -> shared edge, got %v (%v)", deps, err)
	}
}

func TestSubgraphFromHandlesCycles(t *testing.T) {
	g := subgraphFixture(t, [][2]string{
		{"pkg:generic/root", "pkg:generic/a"}, {"pkg:generic/a", "pkg:generic/b"}, {"pkg:generic/b", "pkg:generic/a"},
	})
	sub, err := SubgraphFrom(g, "pkg:generic/root")
	if err != nil {
		t.Fatalf("SubgraphFrom() error = %v", err)
	}
	if sub.Size() != 3 {
		t.Fatalf("expected cycle nodes preserved, got %d nodes", sub.Size())
	}
}

func TestSubgraphFromMissingRoot(t *testing.T) {
	g := subgraphFixture(t, [][2]string{{"pkg:generic/root", "pkg:generic/a"}})
	if _, err := SubgraphFrom(g, "nope"); err == nil {
		t.Fatal("expected error for missing root")
	}
	if _, err := SubgraphFrom(nil, "pkg:generic/root"); err == nil {
		t.Fatal("expected error for nil graph")
	}
}
