package detectorkit_test

import (
	"testing"
	"time"

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
	// Reachable only through the development dependency. It is the node that
	// makes this test mean something: every other package here ends up
	// runtime, which the closing default would produce on its own even if
	// propagation never ran.
	devOnly := testkit.MustDependencyCoords(t, sdk.Coordinates{Ecosystem: sdk.EcosystemPython, Name: "iniconfig", Version: "2.0.0"})
	for _, node := range []sdk.GraphNode{root, dev, runtime, shared, cyclic, devOnly} {
		if err := g.AddNode(node); err != nil {
			t.Fatal(err)
		}
	}
	for _, edge := range [][2]string{
		{root.NodeID(), dev.NodeID()},
		{root.NodeID(), runtime.NodeID()},
		{dev.NodeID(), shared.NodeID()},
		{dev.NodeID(), devOnly.NodeID()},
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
	if devOnly.PrimaryScope() != sdk.ScopeDevelopment {
		t.Fatalf("iniconfig scope = %q, want development carried down the only path that reaches it",
			devOnly.PrimaryScope())
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

// A node the detector already marked runtime, reached only on a development
// path, inside a cycle: the walk used to re-enqueue it forever.
//
// The old termination test required the propagated value *and* the node's own
// primary scope to settle, and those two never agreed here -- runtime on the
// node, development on the path -- so the queue never drained and the process
// hung rather than failed. The topology is small and specific because that is
// what it takes: a plain cycle terminates either way.
func TestPropagateScopesTerminatesWhenANodeOutranksItsPath(t *testing.T) {
	g := sdk.New()
	root := testkit.MustModuleNode(t, "pyproject.toml", sdk.Coordinates{
		Ecosystem: sdk.EcosystemPython, Name: "app", Version: "1.0.0",
	})
	dev := testkit.MustDependencyCoords(t, sdk.Coordinates{Ecosystem: sdk.EcosystemPython, Name: "pytest", Version: "8.0.0"})
	first := testkit.MustDependencyCoords(t, sdk.Coordinates{Ecosystem: sdk.EcosystemPython, Name: "cee", Version: "1.0.0"})
	second := testkit.MustDependencyCoords(t, sdk.Coordinates{Ecosystem: sdk.EcosystemPython, Name: "dee", Version: "1.0.0"})
	// Marked runtime by the detector, and reachable only through the
	// development dependency.
	first.AddScope(sdk.ScopeRuntime)
	second.AddScope(sdk.ScopeRuntime)
	for _, node := range []sdk.GraphNode{root, dev, first, second} {
		if err := g.AddNode(node); err != nil {
			t.Fatal(err)
		}
	}
	for _, edge := range [][2]string{
		{root.NodeID(), dev.NodeID()},
		{dev.NodeID(), first.NodeID()},
		{first.NodeID(), second.NodeID()},
		{second.NodeID(), first.NodeID()},
	} {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatal(err)
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		detectorkit.PropagateScopes(g, root.NodeID(), func(*sdk.DependencyNode) sdk.Scope {
			return sdk.ScopeDevelopment
		})
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("PropagateScopes did not terminate: a node outranking its path re-enqueued forever")
	}

	// And the stronger scope still wins: a package marked runtime is
	// reachable at runtime whichever path found it.
	if first.PrimaryScope() != sdk.ScopeRuntime || second.PrimaryScope() != sdk.ScopeRuntime {
		t.Fatalf("scopes = %q and %q, want runtime to survive the development path",
			first.PrimaryScope(), second.PrimaryScope())
	}
}

// Promotion replaces a node, and RemoveNode is final: anything the detector
// learned before it discovered ownership has to travel across. Locations and
// metadata are what a dependency and a module both hold.
func TestPromoteToModuleCarriesLocationsAndMetadata(t *testing.T) {
	g := sdk.New()
	root := testkit.MustDependencyCoords(t, sdk.Coordinates{
		Ecosystem: sdk.EcosystemMaven, Org: "com.acme", Name: "app", Version: "1.0.0",
	})
	root.Locations = []sdk.PackageLocation{{RealPath: "app/pom.xml", AccessPath: "app/pom.xml"}}
	root.Metadata = map[string]any{"maven": "reactor"}
	if err := g.AddNode(root); err != nil {
		t.Fatal(err)
	}

	promotedID, err := detectorkit.PromoteToModule(g, root.NodeID(), "app/pom.xml")
	if err != nil {
		t.Fatalf("PromoteToModule() error = %v", err)
	}
	promoted, ok := g.Node(promotedID)
	if !ok {
		t.Fatalf("no node at %q after promotion", promotedID)
	}
	module, ok := sdk.AsModuleNode(promoted)
	if !ok {
		t.Fatalf("promoted node is a %s node, want a module", promoted.Kind())
	}
	if len(module.Locations) != 1 || module.Locations[0].RealPath != "app/pom.xml" {
		t.Errorf("locations = %+v, want the ones the dependency carried", module.Locations)
	}
	if module.Metadata["maven"] != "reactor" {
		t.Errorf("metadata = %+v, want what the detector recorded before promotion", module.Metadata)
	}
}

// An edge's kind is recorded on the edge, not derived on read. Re-adding a
// promoted node's edges without it turned an explicit depends-on into a
// describes the moment its target became a module, changing the relationship
// the graph exports.
func TestPromoteToModuleKeepsExplicitEdgeKinds(t *testing.T) {
	g := sdk.New()
	manifest := testkit.MustManifestNode(t, "pom.xml", sdk.ManifestKindPomXML)
	dependency := testkit.MustDependencyCoords(t, sdk.Coordinates{
		Ecosystem: sdk.EcosystemMaven, Org: "com.acme", Name: "app", Version: "1.0.0",
	})
	for _, node := range []sdk.GraphNode{manifest, dependency} {
		if err := g.AddNode(node); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.AddTypedEdge(manifest.NodeID(), dependency.NodeID(), sdk.EdgeKindDependsOn); err != nil {
		t.Fatal(err)
	}

	promotedID, err := detectorkit.PromoteToModule(g, dependency.NodeID(), "app/pom.xml")
	if err != nil {
		t.Fatalf("PromoteToModule() error = %v", err)
	}
	if got := g.EdgeKindOf(manifest.NodeID(), promotedID); got != sdk.EdgeKindDependsOn {
		t.Fatalf("edge kind = %q, want the depends-on the edge was recorded with", got)
	}
}
