package detectorkit_test

import (
	"testing"

	sdk "github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/detectorkit"
	"github.com/bomly-dev/bomly-sdk/testkit"
)

// A lockfile can name one package more than once. The second record folds
// into the first, and the fold must keep what the second witnessed -- the
// scope it was declared at, the place it resolved from -- because that is the
// data the old hand-written existence checks discarded.
func TestEnsureNodeFoldsAndKeepsBothWitnesses(t *testing.T) {
	g := sdk.New()
	coords := sdk.Coordinates{Ecosystem: sdk.EcosystemPython, Name: "requests", Version: "2.31.0"}

	runtime := testkit.MustDependencyCoords(t, coords)
	runtime.AddScope(sdk.ScopeRuntime)
	runtime.Origins = sdk.MergeOrigins(nil, artifactOrigins("https://a.example/requests-2.31.0.tar.gz"))
	first, err := detectorkit.EnsureNode(g, runtime)
	if err != nil {
		t.Fatalf("EnsureNode(first) error = %v", err)
	}

	development := testkit.MustDependencyCoords(t, coords)
	development.AddScope(sdk.ScopeDevelopment)
	development.Origins = sdk.MergeOrigins(nil, artifactOrigins("https://b.example/requests-2.31.0.tar.gz"))
	surviving, err := detectorkit.EnsureNode(g, development)
	if err != nil {
		t.Fatalf("EnsureNode(duplicate) error = %v", err)
	}

	if surviving != first {
		t.Fatal("the duplicate did not fold into the node already present")
	}
	if g.Size() != 1 {
		t.Fatalf("graph size = %d, want one node per identity", g.Size())
	}
	if !surviving.HasScope(sdk.ScopeRuntime) || !surviving.HasScope(sdk.ScopeDevelopment) {
		t.Fatalf("scopes = %v, want the union of both records", surviving.Scopes)
	}
	if len(surviving.Origins) != 2 {
		t.Fatalf("origins = %v, want both resolutions on the folded node", surviving.Origins)
	}
}

// The typed return is the point: a caller inserting a module gets a module
// back, and a nil is tolerated rather than dereferenced.
func TestEnsureNodeIsTypedAndNilTolerant(t *testing.T) {
	g := sdk.New()
	module := testkit.MustModuleNode(t, "package.json", sdk.Coordinates{
		Ecosystem: sdk.EcosystemNPM, Name: "app", Version: "1.0.0",
	})
	surviving, err := detectorkit.EnsureNode(g, module)
	if err != nil {
		t.Fatalf("EnsureNode(module) error = %v", err)
	}
	if surviving.DeclaringManifestPath != "package.json" {
		t.Fatalf("survivor = %+v, want the module back as a module", surviving)
	}

	if got, err := detectorkit.EnsureNode(g, (*sdk.DependencyNode)(nil)); got != nil || err != nil {
		t.Fatalf("EnsureNode(typed nil) = %v, %v; want a no-op", got, err)
	}
	if got, err := detectorkit.EnsureNode[*sdk.ModuleNode](nil, module); got != nil || err != nil {
		t.Fatalf("EnsureNode(nil graph) = %v, %v; want a no-op", got, err)
	}
}

// Maven learns which roots are reactor modules after parsing the tree, and
// which directory declares each one later still, so promotion has to move a
// node that already has edges -- and report the ID it now answers to.
func TestPromoteToModuleKeepsEdgesAndReportsTheNewID(t *testing.T) {
	g := sdk.New()
	root := testkit.MustDependencyCoords(t, sdk.Coordinates{
		Ecosystem: sdk.EcosystemMaven, Org: "com.acme", Name: "app", Version: "1.0.0",
	})
	child := testkit.MustDependencyCoords(t, sdk.Coordinates{
		Ecosystem: sdk.EcosystemMaven, Org: "org.slf4j", Name: "slf4j-api", Version: "2.0.13",
	})
	parent := testkit.MustDependencyCoords(t, sdk.Coordinates{
		Ecosystem: sdk.EcosystemMaven, Org: "com.acme", Name: "aggregator", Version: "1.0.0",
	})
	for _, node := range []sdk.GraphNode{root, child, parent} {
		if err := g.AddNode(node); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.AddEdge(root.NodeID(), child.NodeID()); err != nil {
		t.Fatal(err)
	}
	if err := g.AddEdge(parent.NodeID(), root.NodeID()); err != nil {
		t.Fatal(err)
	}

	promotedID, err := detectorkit.PromoteToModule(g, root.NodeID(), "app/pom.xml")
	if err != nil {
		t.Fatalf("PromoteToModule() error = %v", err)
	}
	if promotedID == root.NodeID() {
		t.Fatal("the promoted node kept its dependency ID")
	}
	promoted, ok := g.Node(promotedID)
	if !ok || !sdk.IsProjectOwned(promoted) {
		t.Fatalf("promoted node = %v, want the project's own module", promoted)
	}
	if _, stillThere := g.Node(root.NodeID()); stillThere {
		t.Fatal("the dependency node survived promotion")
	}

	children, err := g.DirectDependencies(promotedID)
	if err != nil || len(children) != 1 || children[0].NodeID() != child.NodeID() {
		t.Fatalf("children = %v, err = %v; want the outbound edge re-pointed", children, err)
	}
	parents, err := g.Dependents(promotedID)
	if err != nil || len(parents) != 1 || parents[0].NodeID() != parent.NodeID() {
		t.Fatalf("parents = %v, err = %v; want the inbound edge re-pointed", parents, err)
	}

	// Idempotent for the path it is given, and re-mints for a different one.
	again, err := detectorkit.PromoteToModule(g, promotedID, "app/pom.xml")
	if err != nil || again != promotedID {
		t.Fatalf("re-promoting to the same manifest = %q, %v; want a no-op", again, err)
	}
	moved, err := detectorkit.PromoteToModule(g, promotedID, "modules/app/pom.xml")
	if err != nil || moved == promotedID {
		t.Fatalf("re-promoting to another manifest = %q, %v; want a new identity", moved, err)
	}
}

// Runtime beats development on any path that reaches a package, and the walk
// terminates on a cycle -- the trap each hand-written copy of this had to
// re-solve.
func TestPropagateScopesPrefersRuntimeAndTerminatesOnCycles(t *testing.T) {
	g := sdk.New()
	root := testkit.MustModuleNode(t, "pyproject.toml", sdk.Coordinates{
		Ecosystem: sdk.EcosystemPython, Name: "app", Version: "1.0.0",
	})
	dev := testkit.MustDependencyCoords(t, sdk.Coordinates{Ecosystem: sdk.EcosystemPython, Name: "pytest", Version: "8.0.0"})
	runtime := testkit.MustDependencyCoords(t, sdk.Coordinates{Ecosystem: sdk.EcosystemPython, Name: "requests", Version: "2.31.0"})
	shared := testkit.MustDependencyCoords(t, sdk.Coordinates{Ecosystem: sdk.EcosystemPython, Name: "urllib3", Version: "2.2.0"})
	cyclic := testkit.MustDependencyCoords(t, sdk.Coordinates{Ecosystem: sdk.EcosystemPython, Name: "idna", Version: "3.6"})
	for _, node := range []sdk.GraphNode{root, dev, runtime, shared, cyclic} {
		if err := g.AddNode(node); err != nil {
			t.Fatal(err)
		}
	}
	for _, edge := range [][2]string{
		{root.NodeID(), dev.NodeID()},
		{root.NodeID(), runtime.NodeID()},
		{dev.NodeID(), shared.NodeID()},
		{runtime.NodeID(), shared.NodeID()},
		{shared.NodeID(), cyclic.NodeID()},
		{cyclic.NodeID(), shared.NodeID()},
	} {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatal(err)
		}
	}

	seeds := map[string]sdk.Scope{dev.NodeID(): sdk.ScopeDevelopment, runtime.NodeID(): sdk.ScopeRuntime}
	detectorkit.PropagateScopes(g, root.NodeID(), func(node *sdk.DependencyNode) sdk.Scope {
		return seeds[node.NodeID()]
	})

	if dev.PrimaryScope() != sdk.ScopeDevelopment {
		t.Fatalf("pytest scope = %q, want development", dev.PrimaryScope())
	}
	if shared.PrimaryScope() != sdk.ScopeRuntime {
		t.Fatalf("urllib3 scope = %q, want runtime to win over the development path", shared.PrimaryScope())
	}
	if cyclic.PrimaryScope() != sdk.ScopeRuntime {
		t.Fatalf("idna scope = %q, want the cycle walked and scoped", cyclic.PrimaryScope())
	}
	if !sdk.IsProjectOwned(root) {
		t.Fatal("the root module was rewritten by scope propagation")
	}
}

// An unscoped package defaults to runtime: the resolver installed it, so it
// is used unless something said otherwise.
func TestPropagateScopesDefaultsOrphansToRuntime(t *testing.T) {
	g := sdk.New()
	root := testkit.MustModuleNode(t, "pyproject.toml", sdk.Coordinates{
		Ecosystem: sdk.EcosystemPython, Name: "app", Version: "1.0.0",
	})
	orphan := testkit.MustDependencyCoords(t, sdk.Coordinates{Ecosystem: sdk.EcosystemPython, Name: "orphan", Version: "1.0.0"})
	for _, node := range []sdk.GraphNode{root, orphan} {
		if err := g.AddNode(node); err != nil {
			t.Fatal(err)
		}
	}

	detectorkit.PropagateScopes(g, root.NodeID(), nil)

	if orphan.PrimaryScope() != sdk.ScopeRuntime {
		t.Fatalf("orphan scope = %q, want runtime", orphan.PrimaryScope())
	}
}

func artifactOrigins(url string) []sdk.DependencyOrigin {
	origin := sdk.ArtifactOrigin(url)
	if origin == nil {
		return nil
	}
	return []sdk.DependencyOrigin{*origin}
}
