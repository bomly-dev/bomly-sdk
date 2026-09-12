package sdk

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestNewDependencyNode_MintsCanonicalPURLID(t *testing.T) {
	// IDs are canonical package URLs now: name+version mints pkg:generic.
	n := mustDep(t, Coordinates{Name: "react", Version: "18.2.0"})
	if n.NodeID() != "pkg:generic/react@18.2.0" {
		t.Fatalf("expected ID pkg:generic/react@18.2.0, got %q", n.NodeID())
	}
	if n.Coordinates.PURL != n.NodeID() {
		t.Fatalf("expected coordinates PURL to match the node ID, got %q", n.Coordinates.PURL)
	}
}

func TestNewDependencyNode_StoresCoordinatesAndBuildsID(t *testing.T) {
	n := mustDep(t, Coordinates{Ecosystem: EcosystemMaven,
		Name:           "demo-artifact:sources",
		Version:        "1.0.0",
		Org:            "com.example",
		PackageManager: PackageManagerMaven,
	})

	// IDs are canonical package URLs now.
	if n.NodeID() != "pkg:maven/com.example/demo-artifact:sources@1.0.0" {
		t.Fatalf("expected canonical purl ID, got %q", n.NodeID())
	}
	if n.QualifiedName() != "com.example:demo-artifact:sources" {
		t.Fatalf("expected qualified name, got %q", n.QualifiedName())
	}
	if n.Ecosystem != EcosystemMaven || n.Org != "com.example" || n.PackageManager != PackageManagerMaven {
		t.Fatalf("unexpected coordinates on dependency: %#v", n)
	}
}

func TestAddNodeAndDependency_Success(t *testing.T) {
	g := New()
	app := mustDep(t, Coordinates{Name: "app", Version: "1.0.0"})
	react := mustDep(t, Coordinates{Name: "react", Version: "18.2.0"})

	if err := g.AddNode(app); err != nil {
		t.Fatalf("add app node: %v", err)
	}
	if err := g.AddNode(react); err != nil {
		t.Fatalf("add react node: %v", err)
	}
	if err := g.AddEdge(app.NodeID(), react.NodeID()); err != nil {
		t.Fatalf("add edge: %v", err)
	}

	deps, err := g.DirectDependencies(app.NodeID())
	if err != nil {
		t.Fatalf("direct dependencies: %v", err)
	}
	if len(deps) != 1 || deps[0].NodeID() != react.NodeID() {
		t.Fatalf("expected app to depend on react, got %#v", deps)
	}

	dependents, err := g.Dependents(react.NodeID())
	if err != nil {
		t.Fatalf("dependents: %v", err)
	}
	if len(dependents) != 1 || dependents[0].NodeID() != app.NodeID() {
		t.Fatalf("expected react dependent app, got %#v", dependents)
	}
}

func TestAddEdge_AllowsCycles(t *testing.T) {
	g := New()
	a := mustDep(t, Coordinates{Name: "a"})
	b := mustDep(t, Coordinates{Name: "b"})
	c := mustDep(t, Coordinates{Name: "c"})

	for _, n := range []*DependencyNode{a, b, c} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.NodeID(), err)
		}
	}
	if err := g.AddEdge(a.NodeID(), b.NodeID()); err != nil {
		t.Fatalf("add edge a->b: %v", err)
	}
	if err := g.AddEdge(b.NodeID(), c.NodeID()); err != nil {
		t.Fatalf("add edge b->c: %v", err)
	}
	if err := g.AddEdge(c.NodeID(), a.NodeID()); err != nil {
		t.Fatalf("add edge c->a: %v", err)
	}

	deps, err := g.DirectDependencies(c.NodeID())
	if err != nil {
		t.Fatalf("direct dependencies(c): %v", err)
	}
	if len(deps) != 1 || deps[0].NodeID() != a.NodeID() {
		t.Fatalf("expected c to depend on a, got %#v", deps)
	}
}

func TestTopologicalSort(t *testing.T) {
	g := New()
	app := mustDep(t, Coordinates{Name: "app"})
	api := mustDep(t, Coordinates{Name: "api"})
	log := mustDep(t, Coordinates{Name: "log"})
	util := mustDep(t, Coordinates{Name: "util"})

	for _, n := range []*DependencyNode{app, api, log, util} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.NodeID(), err)
		}
	}
	if err := g.AddEdge(app.NodeID(), api.NodeID()); err != nil {
		t.Fatalf("add app->api: %v", err)
	}
	if err := g.AddEdge(api.NodeID(), util.NodeID()); err != nil {
		t.Fatalf("add api->util: %v", err)
	}
	if err := g.AddEdge(app.NodeID(), log.NodeID()); err != nil {
		t.Fatalf("add app->log: %v", err)
	}

	order, err := g.TopologicalSort()
	if err != nil {
		t.Fatalf("topological sort: %v", err)
	}

	ids := idsOf(order)

	assertBefore(t, ids, app.NodeID(), api.NodeID())
	assertBefore(t, ids, app.NodeID(), log.NodeID())
	assertBefore(t, ids, api.NodeID(), util.NodeID())
}

func TestTopologicalSort_ReturnsPartialOrderOnCycle(t *testing.T) {
	g := New()
	a := mustDep(t, Coordinates{Name: "a"})
	b := mustDep(t, Coordinates{Name: "b"})
	c := mustDep(t, Coordinates{Name: "c"})

	for _, n := range []*DependencyNode{a, b, c} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.NodeID(), err)
		}
	}
	for _, edge := range [][2]string{{a.NodeID(), b.NodeID()}, {b.NodeID(), a.NodeID()}} {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("add edge %q -> %q: %v", edge[0], edge[1], err)
		}
	}

	order, err := g.TopologicalSort()
	if !errors.Is(err, ErrCycleDetected) {
		t.Fatalf("expected cycle error, got %v", err)
	}
	if got := idsOf(order); !slices.Equal(got, []string{"pkg:generic/c"}) {
		t.Fatalf("expected partial order [pkg:generic/c], got %#v", got)
	}
}

func TestRootsAndLeaves(t *testing.T) {
	g := New()
	app := mustDep(t, Coordinates{Name: "app"})
	react := mustDep(t, Coordinates{Name: "react"})
	lodash := mustDep(t, Coordinates{Name: "lodash"})

	for _, n := range []*DependencyNode{app, react, lodash} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.NodeID(), err)
		}
	}
	if err := g.AddEdge(app.NodeID(), react.NodeID()); err != nil {
		t.Fatalf("add edge: %v", err)
	}

	roots := idsOf(g.Roots())
	leaves := idsOf(g.Leaves())

	if !slices.Equal(roots, []string{"pkg:generic/app", "pkg:generic/lodash"}) {
		t.Fatalf("unexpected roots: %#v", roots)
	}
	if !slices.Equal(leaves, []string{"pkg:generic/lodash", "pkg:generic/react"}) {
		t.Fatalf("unexpected leaves: %#v", leaves)
	}
}

func TestCollectPathsTo_PrunesIrrelevantBranches(t *testing.T) {
	g := New()
	app := mustDep(t, Coordinates{Name: "app"})
	left := mustDep(t, Coordinates{Name: "left"})
	target := mustDep(t, Coordinates{Name: "target"})
	irrelevantA := mustDep(t, Coordinates{Name: "irrelevant-a"})
	irrelevantB := mustDep(t, Coordinates{Name: "irrelevant-b"})

	for _, n := range []*DependencyNode{app, left, target, irrelevantA, irrelevantB} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.NodeID(), err)
		}
	}
	for _, edge := range [][2]string{{app.NodeID(), left.NodeID()}, {left.NodeID(), target.NodeID()}, {app.NodeID(), irrelevantA.NodeID()}, {irrelevantA.NodeID(), irrelevantB.NodeID()}, {irrelevantB.NodeID(), irrelevantA.NodeID()}} {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("add edge %q -> %q: %v", edge[0], edge[1], err)
		}
	}

	paths, err := g.CollectPathsTo(target.NodeID())
	if err != nil {
		t.Fatalf("CollectPathsTo(): %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %#v", paths)
	}
	assertCollectedPath(t, paths[0], false, "", []string{"pkg:generic/app", "pkg:generic/left", "pkg:generic/target"})
	for _, path := range paths {
		for _, node := range path.Nodes {
			if strings.Contains(node.NodeID(), "irrelevant") {
				t.Fatalf("unexpected irrelevant node in path %#v", idsOf(path.Nodes))
			}
		}
	}
}

func TestCollectPathsTo_RecordsTargetCycle(t *testing.T) {
	g := New()
	app := mustDep(t, Coordinates{Name: "app"})
	b := mustDep(t, Coordinates{Name: "b"})
	c := mustDep(t, Coordinates{Name: "c"})

	for _, n := range []*DependencyNode{app, b, c} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.NodeID(), err)
		}
	}
	for _, edge := range [][2]string{{app.NodeID(), b.NodeID()}, {b.NodeID(), c.NodeID()}, {c.NodeID(), b.NodeID()}} {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("add edge %q -> %q: %v", edge[0], edge[1], err)
		}
	}

	paths, err := g.CollectPathsTo(b.NodeID())
	if err != nil {
		t.Fatalf("CollectPathsTo(): %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %#v", paths)
	}
	assertCollectedPath(t, paths[0], false, "", []string{"pkg:generic/app", "pkg:generic/b"})
	assertCollectedPath(t, paths[1], true, b.NodeID(), []string{"pkg:generic/app", "pkg:generic/b", "pkg:generic/c", "pkg:generic/b"})
}

func TestCollectPathsTo_RootlessCycleFallsBackToRelevantNodes(t *testing.T) {
	g := New()
	a := mustDep(t, Coordinates{Name: "a"})
	b := mustDep(t, Coordinates{Name: "b"})
	c := mustDep(t, Coordinates{Name: "c"})
	x := mustDep(t, Coordinates{Name: "x"})
	y := mustDep(t, Coordinates{Name: "y"})

	for _, n := range []*DependencyNode{a, b, c, x, y} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.NodeID(), err)
		}
	}
	for _, edge := range [][2]string{{a.NodeID(), b.NodeID()}, {b.NodeID(), c.NodeID()}, {c.NodeID(), a.NodeID()}, {x.NodeID(), y.NodeID()}, {y.NodeID(), x.NodeID()}} {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("add edge %q -> %q: %v", edge[0], edge[1], err)
		}
	}

	paths, err := g.CollectPathsTo(b.NodeID())
	if err != nil {
		t.Fatalf("CollectPathsTo(): %v", err)
	}
	if len(paths) != 4 {
		t.Fatalf("expected 4 paths, got %#v", paths)
	}
	assertCollectedPath(t, paths[0], false, "", []string{"pkg:generic/a", "pkg:generic/b"})
	assertCollectedPath(t, paths[1], false, "", []string{"pkg:generic/b"})
	assertCollectedPath(t, paths[2], true, b.NodeID(), []string{"pkg:generic/b", "pkg:generic/c", "pkg:generic/a", "pkg:generic/b"})
	assertCollectedPath(t, paths[3], false, "", []string{"pkg:generic/c", "pkg:generic/a", "pkg:generic/b"})
}

func TestRemoveNode_RemovesIncidentEdges(t *testing.T) {
	g := New()
	a := mustDep(t, Coordinates{Name: "a"})
	b := mustDep(t, Coordinates{Name: "b"})
	c := mustDep(t, Coordinates{Name: "c"})

	for _, n := range []*DependencyNode{a, b, c} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.NodeID(), err)
		}
	}
	if err := g.AddEdge(a.NodeID(), b.NodeID()); err != nil {
		t.Fatalf("add a->b: %v", err)
	}
	if err := g.AddEdge(c.NodeID(), b.NodeID()); err != nil {
		t.Fatalf("add c->b: %v", err)
	}

	if ok := g.RemoveNode(b.NodeID()); !ok {
		t.Fatalf("expected node b removal to succeed")
	}

	if _, ok := g.Node(b.NodeID()); ok {
		t.Fatalf("expected node b removed")
	}
	if deps, err := g.DirectDependencies(a.NodeID()); err != nil || len(deps) != 0 {
		t.Fatalf("expected a dependencies cleared, deps=%#v err=%v", deps, err)
	}
}

func TestPrettyString(t *testing.T) {
	g := New()
	app := mustDep(t, Coordinates{Name: "app"})
	react := mustDep(t, Coordinates{Name: "react", Version: "18.2.0"})
	zod := mustDep(t, Coordinates{Name: "zod"})

	for _, n := range []*DependencyNode{app, react, zod} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.NodeID(), err)
		}
	}
	if err := g.AddEdge(app.NodeID(), react.NodeID()); err != nil {
		t.Fatalf("add edge: %v", err)
	}
	if err := g.AddEdge(app.NodeID(), zod.NodeID()); err != nil {
		t.Fatalf("add edge: %v", err)
	}

	got := g.PrettyString()
	want := "pkg:generic/app -> [pkg:generic/react@18.2.0, pkg:generic/zod]\npkg:generic/react@18.2.0 -> []\npkg:generic/zod -> []"
	if got != want {
		t.Fatalf("unexpected pretty string:\nwant:\n%s\n\ngot:\n%s", want, got)
	}
}

func TestPrettyTree_WithSharedDependency(t *testing.T) {
	g := New()
	a := mustDep(t, Coordinates{Name: "a"})
	b := mustDep(t, Coordinates{Name: "b"})
	c := mustDep(t, Coordinates{Name: "c"})

	for _, n := range []*DependencyNode{a, b, c} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.NodeID(), err)
		}
	}
	if err := g.AddEdge(a.NodeID(), b.NodeID()); err != nil {
		t.Fatalf("add a->b: %v", err)
	}
	if err := g.AddEdge(c.NodeID(), b.NodeID()); err != nil {
		t.Fatalf("add c->b: %v", err)
	}

	got := g.PrettyTree()
	want := "pkg:generic/a\n`-- pkg:generic/b\npkg:generic/c\n`-- pkg:generic/b (shared)"
	if got != want {
		t.Fatalf("unexpected pretty tree:\nwant:\n%s\n\ngot:\n%s", want, got)
	}
}

func TestPrettyTree_WithCycle(t *testing.T) {
	g := New()
	app := mustDep(t, Coordinates{Name: "app"})
	a := mustDep(t, Coordinates{Name: "a"})
	b := mustDep(t, Coordinates{Name: "b"})

	for _, n := range []*DependencyNode{app, a, b} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.NodeID(), err)
		}
	}
	for _, edge := range [][2]string{{app.NodeID(), a.NodeID()}, {a.NodeID(), b.NodeID()}, {b.NodeID(), a.NodeID()}} {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("add edge %q -> %q: %v", edge[0], edge[1], err)
		}
	}

	got := g.PrettyTree()
	want := "pkg:generic/app\n`-- pkg:generic/a\n    `-- pkg:generic/b\n        `-- pkg:generic/a (cycle)"
	if got != want {
		t.Fatalf("unexpected pretty tree:\nwant:\n%s\n\ngot:\n%s", want, got)
	}
}

func TestReAddNodeAfterRemove_ReusesGraphState(t *testing.T) {
	g := New()
	a := mustDep(t, Coordinates{Name: "a"})
	b := mustDep(t, Coordinates{Name: "b"})
	c := mustDep(t, Coordinates{Name: "c"})

	for _, n := range []*DependencyNode{a, b, c} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %q: %v", n.NodeID(), err)
		}
	}
	if err := g.AddEdge(a.NodeID(), b.NodeID()); err != nil {
		t.Fatalf("add a->b: %v", err)
	}
	if err := g.AddEdge(c.NodeID(), b.NodeID()); err != nil {
		t.Fatalf("add c->b: %v", err)
	}

	if ok := g.RemoveNode(b.NodeID()); !ok {
		t.Fatalf("remove b failed")
	}

	d := mustDep(t, Coordinates{Name: "d"})
	if err := g.AddNode(d); err != nil {
		t.Fatalf("add d: %v", err)
	}
	if err := g.AddEdge(a.NodeID(), d.NodeID()); err != nil {
		t.Fatalf("add a->d: %v", err)
	}
	if err := g.AddEdge(c.NodeID(), d.NodeID()); err != nil {
		t.Fatalf("add c->d: %v", err)
	}

	if got := g.Size(); got != 3 {
		t.Fatalf("expected size 3, got %d", got)
	}
	deps, err := g.DirectDependencies(a.NodeID())
	if err != nil {
		t.Fatalf("direct dependencies(a): %v", err)
	}
	if len(deps) != 1 || deps[0].NodeID() != d.NodeID() {
		t.Fatalf("expected a to depend on d, got %#v", deps)
	}
}

func TestCompare_ClassifiesAddedRemovedAndUpdated(t *testing.T) {
	base := New()
	head := New()

	// The application root is a module node under the union; modules are
	// structural and never diff.
	baseApp := mustModule(t, "package.json", Coordinates{Name: "app", Version: "1.0.0"})
	baseKeep := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "keep", Version: "1.0.0"})
	baseRemove := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "remove", Version: "1.0.0"})
	baseUpdate := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "update", Version: "1.0.0"})
	headApp := mustModule(t, "package.json", Coordinates{Name: "app", Version: "1.0.0"})
	headKeep := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "keep", Version: "1.0.0"})
	headAdd := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "add", Version: "2.0.0"})
	headUpdate := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "update", Version: "2.0.0"})

	for _, node := range []GraphNode{baseApp, baseKeep, baseRemove, baseUpdate} {
		if err := base.AddNode(node); err != nil {
			t.Fatalf("base.AddNode(%q): %v", node.NodeID(), err)
		}
	}
	for _, node := range []GraphNode{headApp, headKeep, headAdd, headUpdate} {
		if err := head.AddNode(node); err != nil {
			t.Fatalf("head.AddNode(%q): %v", node.NodeID(), err)
		}
	}

	diff := Compare(base, head)
	if got := depIDsOf(diff.Added); !slices.Equal(got, []string{"pkg:npm/add@2.0.0"}) {
		t.Fatalf("unexpected added nodes: %#v", got)
	}
	if got := depIDsOf(diff.Removed); !slices.Equal(got, []string{"pkg:npm/remove@1.0.0"}) {
		t.Fatalf("unexpected removed nodes: %#v", got)
	}
	if len(diff.Updated) != 1 {
		t.Fatalf("expected one updated node, got %#v", diff.Updated)
	}
	if diff.Updated[0].Before.NodeID() != "pkg:npm/update@1.0.0" || diff.Updated[0].After.NodeID() != "pkg:npm/update@2.0.0" {
		t.Fatalf("unexpected updated node: %#v", diff.Updated[0])
	}
	if len(diff.Transitions) != 0 {
		t.Fatalf("unexpected detail changes: %#v", diff.Transitions)
	}
}

func TestCompare_ClassifiesDependencyDetailTransitions(t *testing.T) {
	base := New()
	head := New()
	// The first-party application root is a module node under the union.
	baseRoot := mustModule(t, "package.json", Coordinates{Type: PackageTypeApplication, Name: "app"})
	headRoot := baseRoot.Clone()
	baseDependency := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "example", Version: "1.0.0"})
	baseDependency.Relationship = DependencyRelationshipDirect
	baseDependency.Source = DependencySourceRegistry
	headDependency := baseDependency.Clone()
	headDependency.Relationship = DependencyRelationshipUnknown
	headDependency.Source = DependencySourceGit

	for _, pair := range []struct {
		graph *Graph
		root  *ModuleNode
		dep   *DependencyNode
	}{
		{graph: base, root: baseRoot, dep: baseDependency},
		{graph: head, root: headRoot, dep: headDependency},
	} {
		if err := pair.graph.AddNode(pair.root); err != nil {
			t.Fatal(err)
		}
		if err := pair.graph.AddNode(pair.dep); err != nil {
			t.Fatal(err)
		}
		if err := pair.graph.AddEdge(pair.root.NodeID(), pair.dep.NodeID()); err != nil {
			t.Fatal(err)
		}
	}

	diff := Compare(base, head)
	if len(diff.Added) != 0 || len(diff.Removed) != 0 || len(diff.Updated) != 0 {
		t.Fatalf("detail-only diff changed package identity/version buckets: %#v", diff)
	}
	if len(diff.Transitions) != 1 {
		t.Fatalf("Transitions = %#v, want one", diff.Transitions)
	}
	transition := diff.Transitions[0]
	wantFields := []DependencyDetailField{
		DependencyDetailSource,
		DependencyDetailRegistryEligibility,
	}
	if !slices.Equal(transition.ChangedFields, wantFields) {
		t.Fatalf("ChangedFields = %#v, want %#v", transition.ChangedFields, wantFields)
	}
	if transition.BeforeRelationship != DependencyRelationshipDirect || transition.AfterRelationship != DependencyRelationshipUnknown {
		t.Fatalf("relationship transition = %q -> %q", transition.BeforeRelationship, transition.AfterRelationship)
	}
	if !transition.BeforeRegistryEligible || transition.AfterRegistryEligible {
		t.Fatalf("registry eligibility transition = %t -> %t", transition.BeforeRegistryEligible, transition.AfterRegistryEligible)
	}
}

func TestCompareDependencyDetailsClassifiesEachAxisIndependently(t *testing.T) {
	newBase := func() *DependencyNode {
		base := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "example", Version: "1.0.0"})
		base.Relationship = DependencyRelationshipDirect
		base.Source = DependencySourceRegistry
		return base
	}
	tests := []struct {
		name   string
		before func() *DependencyNode
		after  func() *DependencyNode
		want   DependencyDetailField
	}{
		{
			name:   "relationship only",
			before: newBase,
			after: func() *DependencyNode {
				after := newBase().Clone()
				after.Relationship = DependencyRelationshipTransitive
				return after
			},
			want: DependencyDetailRelationship,
		},
		{
			name:   "known source only",
			before: newBase,
			after: func() *DependencyNode {
				after := newBase().Clone()
				after.Source = DependencySource("custom-registry")
				return after
			},
			want: DependencyDetailSource,
		},
		{
			// Eligibility is derived from source and ecosystem now (the
			// FirstParty flag is gone): the Swift source-control special case
			// is the remaining lever that flips eligibility with an unchanged
			// source value.
			name: "registry eligibility only",
			before: func() *DependencyNode {
				before := mustDepPURL(t, "pkg:swift/github.com/acme/example@1.0.0")
				before.Relationship = DependencyRelationshipDirect
				before.Source = DependencySourceGit
				return before
			},
			after: func() *DependencyNode {
				after := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "example", Version: "1.0.0"})
				after.Relationship = DependencyRelationshipDirect
				after.Source = DependencySourceGit
				return after
			},
			want: DependencyDetailRegistryEligibility,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transition, changed := CompareDependencyDetails(nil, nil, tt.before(), tt.after())
			if !changed {
				t.Fatal("CompareDependencyDetails() did not report a transition")
			}
			if len(transition.ChangedFields) != 1 || transition.ChangedFields[0] != tt.want {
				t.Fatalf("ChangedFields = %#v, want [%s]", transition.ChangedFields, tt.want)
			}
		})
	}
}

func TestCompareDependencyDetailsIgnoresMissingEvidence(t *testing.T) {
	before := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "example", Version: "1.0.0"})
	before.Relationship = DependencyRelationshipUnknown
	after := before.Clone()
	after.Relationship = DependencyRelationshipDirect
	after.Source = DependencySourceRegistry

	if transition, changed := CompareDependencyDetails(nil, nil, before, after); changed {
		t.Fatalf("missing relationship/source evidence must not create a detail change: %#v", transition)
	}
}

func TestDependencyDetailTransitionReviewReasons(t *testing.T) {
	depWithSource := func(source DependencySource) *DependencyNode {
		node := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "example", Version: "1.0.0"})
		node.Source = source
		return node
	}
	dependency := depWithSource(DependencySourceRegistry)
	tests := []struct {
		name       string
		transition DependencyDetailTransition
		want       []DependencyDetailReviewReason
	}{
		{
			name: "source changed to Git",
			transition: DependencyDetailTransition{
				Before:                 dependency,
				After:                  depWithSource(DependencySourceGit),
				ChangedFields:          []DependencyDetailField{DependencyDetailSource, DependencyDetailRegistryEligibility},
				BeforeRegistryEligible: true,
			},
			want: []DependencyDetailReviewReason{
				DependencyDetailReviewSourceGit,
			},
		},
		{
			name: "source changed to URL",
			transition: DependencyDetailTransition{
				Before:        dependency,
				After:         depWithSource(DependencySourceURL),
				ChangedFields: []DependencyDetailField{DependencyDetailSource},
			},
			want: []DependencyDetailReviewReason{DependencyDetailReviewSourceURL},
		},
		{
			name: "coverage gain",
			transition: DependencyDetailTransition{
				Before:                dependency,
				After:                 dependency,
				ChangedFields:         []DependencyDetailField{DependencyDetailRegistryEligibility},
				AfterRegistryEligible: true,
			},
		},
		{
			name: "relationship only",
			transition: DependencyDetailTransition{
				Before:        dependency,
				After:         dependency,
				ChangedFields: []DependencyDetailField{DependencyDetailRelationship},
			},
		},
		{
			name: "missing changed-field evidence",
			transition: DependencyDetailTransition{
				Before: dependency,
				After:  depWithSource(DependencySourceGit),
			},
		},
		{
			name: "missing previous source evidence",
			transition: DependencyDetailTransition{
				Before:        depWithSource(""),
				After:         depWithSource(DependencySourceGit),
				ChangedFields: []DependencyDetailField{DependencyDetailSource},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.transition.ReviewReasons()
			if !slices.Equal(got, tt.want) {
				t.Fatalf("ReviewReasons() = %#v, want %#v", got, tt.want)
			}
			if tt.transition.NeedsReview() != (len(tt.want) > 0) {
				t.Fatalf("NeedsReview() = %t, want %t", tt.transition.NeedsReview(), len(tt.want) > 0)
			}
		})
	}
}

func TestCloneDependencyDetailTransitionsDeepCopiesEvidence(t *testing.T) {
	before := mustDep(t, Coordinates{Name: "example", Version: "1.0.0"})
	before.Source = DependencySourceRegistry
	after := before.Clone()
	after.Source = DependencySourceGit
	original := []DependencyDetailTransition{{
		Before:        before,
		After:         after,
		ChangedFields: []DependencyDetailField{DependencyDetailSource},
	}}

	cloned := CloneDependencyDetailTransitions(original)
	cloned[0].Before.Source = DependencySourceURL
	cloned[0].After.Source = DependencySourceFile
	cloned[0].ChangedFields[0] = DependencyDetailRelationship

	if original[0].Before.Source != DependencySourceRegistry ||
		original[0].After.Source != DependencySourceGit ||
		original[0].ChangedFields[0] != DependencyDetailSource {
		t.Fatalf("clone mutated original: %#v", original)
	}
	if CloneDependencyDetailTransitions(nil) != nil {
		t.Fatal("nil transition slice must stay nil")
	}
}

func TestCompareSortsDependencyDetailTransitions(t *testing.T) {
	base := New()
	head := New()
	for _, name := range []string{"zeta", "alpha"} {
		before := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: name, Version: "1.0.0"})
		before.Source = DependencySourceRegistry
		after := before.Clone()
		after.Source = DependencySourceGit
		if err := base.AddNode(before); err != nil {
			t.Fatal(err)
		}
		if err := head.AddNode(after); err != nil {
			t.Fatal(err)
		}
	}

	diff := Compare(base, head)
	if len(diff.Transitions) != 2 {
		t.Fatalf("Transitions = %#v, want two", diff.Transitions)
	}
	if diff.Transitions[0].Before.Name != "alpha" || diff.Transitions[1].Before.Name != "zeta" {
		t.Fatalf("transitions are not stable: %#v", diff.Transitions)
	}
}

func TestCompare_DerivesRelationshipTransitionFromGraphEdges(t *testing.T) {
	base := New()
	head := New()
	// The first-party application root is a module node under the union.
	appID := ""
	parentID := ""
	childID := ""
	for _, graph := range []*Graph{base, head} {
		app := mustModule(t, "package.json", Coordinates{Type: PackageTypeApplication, Name: "app"})
		parent := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "parent", Version: "1.0.0"})
		child := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "child", Version: "1.0.0"})
		appID, parentID, childID = app.NodeID(), parent.NodeID(), child.NodeID()
		for _, node := range []GraphNode{app, parent, child} {
			if err := graph.AddNode(node); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := base.AddEdge(appID, childID); err != nil {
		t.Fatal(err)
	}
	if err := base.AddEdge(appID, parentID); err != nil {
		t.Fatal(err)
	}
	if err := head.AddEdge(appID, parentID); err != nil {
		t.Fatal(err)
	}
	if err := head.AddEdge(parentID, childID); err != nil {
		t.Fatal(err)
	}

	diff := Compare(base, head)
	if len(diff.Transitions) != 1 {
		t.Fatalf("Transitions = %#v, want one", diff.Transitions)
	}
	transition := diff.Transitions[0]
	if !slices.Equal(transition.ChangedFields, []DependencyDetailField{DependencyDetailRelationship}) {
		t.Fatalf("ChangedFields = %#v", transition.ChangedFields)
	}
	if transition.BeforeRelationship != DependencyRelationshipDirect || transition.AfterRelationship != DependencyRelationshipTransitive {
		t.Fatalf("relationship transition = %q -> %q", transition.BeforeRelationship, transition.AfterRelationship)
	}
}

func TestCompare_ReportsVersionAndDetailChangesSeparately(t *testing.T) {
	base := New()
	head := New()
	before := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "example", Version: "1.0.0"})
	before.Relationship = DependencyRelationshipDirect
	before.Source = DependencySourceRegistry
	after := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "example", Version: "2.0.0"})
	after.Relationship = DependencyRelationshipTransitive
	after.Source = DependencySourceRegistry
	if err := base.AddNode(before); err != nil {
		t.Fatal(err)
	}
	if err := head.AddNode(after); err != nil {
		t.Fatal(err)
	}

	diff := Compare(base, head)
	if len(diff.Updated) != 1 || len(diff.Transitions) != 1 {
		t.Fatalf("Compare() = %#v, want one version change and one detail change", diff)
	}
	if !slices.Equal(diff.Transitions[0].ChangedFields, []DependencyDetailField{DependencyDetailRelationship}) {
		t.Fatalf("ChangedFields = %#v", diff.Transitions[0].ChangedFields)
	}
}

func TestCompare_IgnoresSyntheticSubprojectRoots(t *testing.T) {
	base := New()
	head := New()
	for _, g := range []*Graph{base, head} {
		// Synthetic subproject roots are module nodes under the union;
		// module nodes never diff.
		for _, node := range []GraphNode{
			mustModule(t, "package.json", Coordinates{Name: "root"}),
			mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "shared", Version: "1.0.0"}),
		} {
			if err := g.AddNode(node); err != nil {
				t.Fatalf("AddNode(%q): %v", node.NodeID(), err)
			}
		}
	}

	diff := Compare(base, head)
	if len(diff.Added) != 0 || len(diff.Removed) != 0 || len(diff.Updated) != 0 {
		t.Fatalf("expected empty diff, got %#v", diff)
	}
}

func TestCompareIgnoresManifestAndRootNodes(t *testing.T) {
	base := New()
	head := New()
	// Manifest records and first-party roots are ManifestNode and ModuleNode
	// kinds under the union; only dependency nodes diff.
	for _, node := range []GraphNode{
		mustModule(t, "requirements.txt", Coordinates{Name: "root"}),
		mustManifest(t, "requirements.txt"),
		mustDep(t, Coordinates{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM, Name: "react", Version: "18.2.0"}),
	} {
		if err := head.AddNode(node); err != nil {
			t.Fatalf("head add node %q: %v", node.NodeID(), err)
		}
	}
	if err := base.AddNode(mustDep(t, Coordinates{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM, Name: "react", Version: "18.2.0"})); err != nil {
		t.Fatalf("base add node: %v", err)
	}

	diff := Compare(base, head)
	if len(diff.Added) != 0 || len(diff.Removed) != 0 || len(diff.Updated) != 0 {
		t.Fatalf("expected manifest/root nodes to be ignored, got %#v", diff)
	}
}

func TestCompareIncludesImportedApplicationNodes(t *testing.T) {
	// Application-typed imported components are dependency nodes and diff now
	// (ADR-0041): application type alone is never an ownership signal.
	base := New()
	head := New()
	if err := head.AddNode(mustDep(t, Coordinates{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM, Name: "demo", Version: "1.0.0", Type: PackageTypeApplication})); err != nil {
		t.Fatalf("head add application: %v", err)
	}

	diff := Compare(base, head)
	if got := depIDsOf(diff.Added); !slices.Equal(got, []string{"pkg:npm/demo@1.0.0"}) {
		t.Fatalf("expected the imported application node to diff as added, got %#v", diff)
	}
	if len(diff.Removed) != 0 || len(diff.Updated) != 0 {
		t.Fatalf("unexpected removed/updated entries: %#v", diff)
	}
}

func TestEnrichableNodesAreDependencyNodes(t *testing.T) {
	// NodeIsEnrichable is gone: enrichable and diffable are the dependency
	// kind itself. DependencyNodes() is the enrichment iteration surface.
	g := New()
	for _, node := range []GraphNode{
		mustManifest(t, "pom.xml"),
		mustModule(t, "pom.xml", Coordinates{Ecosystem: EcosystemMaven, Org: "com.acme", Name: "my-module", Version: "1.0.0", Type: PackageTypeApplication}),
		// An application type imported from an SBOM is an artifact kind, not
		// an ownership signal: it stays a dependency node and stays enrichable.
		mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "bundled-app", Version: "2.0.0", Type: PackageTypeApplication}),
		mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "lodash", Version: "4.17.15"}),
		mustDep(t, Coordinates{Name: "guava", Version: "31.0"}),
	} {
		if err := g.AddNode(node); err != nil {
			t.Fatalf("AddNode(%q): %v", node.NodeID(), err)
		}
	}

	got := depIDsOf(g.DependencyNodes())
	want := []string{
		"pkg:generic/guava@31.0",
		"pkg:npm/bundled-app@2.0.0",
		"pkg:npm/lodash@4.17.15",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("DependencyNodes() = %#v, want %#v", got, want)
	}
}

func TestPackageHelpers(t *testing.T) {
	pkg := &Package{Coordinates: Coordinates{PURL: "pkg:generic/acme/demo@1.0.0",
		Org:     "acme",
		Name:    "demo",
		Version: "1.0.0"}, Licenses: []PackageLicense{
		{Value: "MIT"},
		{SPDXExpression: "Apache-2.0"},
		{},
	},
	}

	if got := pkg.DisplayName(); got != "acme:demo" {
		t.Fatalf("DisplayName() = %q, want %q", got, "acme:demo")
	}

	licenses := pkg.LicenseValues()
	if len(licenses) != 2 || licenses[0] != "Apache-2.0" || licenses[1] != "MIT" {
		t.Fatalf("LicenseValues() = %#v", licenses)
	}
}

func assertBefore(t *testing.T, ids []string, first, second string) {
	t.Helper()
	i := slices.Index(ids, first)
	j := slices.Index(ids, second)
	if i == -1 || j == -1 || i >= j {
		t.Fatalf("expected %q before %q in order %#v", first, second, ids)
	}
}

func idsOf(nodes []GraphNode) []string {
	ids := make([]string, 0, len(nodes))
	for _, n := range nodes {
		ids = append(ids, n.NodeID())
	}
	return ids
}

func depIDsOf(nodes []*DependencyNode) []string {
	ids := make([]string, 0, len(nodes))
	for _, n := range nodes {
		ids = append(ids, n.NodeID())
	}
	return ids
}

func assertCollectedPath(t *testing.T, path Path, cyclic bool, cycleTo string, want []string) {
	t.Helper()
	if path.Cyclic != cyclic {
		t.Fatalf("expected cyclic=%t, got %#v", cyclic, path)
	}
	if path.CycleTo != cycleTo {
		t.Fatalf("expected cycleTo=%q, got %#v", cycleTo, path)
	}
	if got := idsOf(path.Nodes); !slices.Equal(got, want) {
		t.Fatalf("expected path %v, got %v", want, got)
	}
}
