package sdk

import (
	"encoding/json"
	"errors"
	"testing"
)

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

func TestAddNodeRejectsTypedNilPointers(t *testing.T) {
	// A failed constructor's zero return is a typed nil: a non-nil
	// interface whose methods would panic. Insertion must report
	// ErrNilNode instead of crashing.
	graph := New()
	var dep *DependencyNode
	var module *ModuleNode
	var manifest *ManifestNode
	for _, node := range []GraphNode{dep, module, manifest, nil} {
		if err := graph.AddNode(node); !errors.Is(err, ErrNilNode) {
			t.Fatalf("AddNode(%T nil) = %v, want ErrNilNode", node, err)
		}
		if _, err := graph.InsertNode(node); !errors.Is(err, ErrNilNode) {
			t.Fatalf("InsertNode(%T nil) = %v, want ErrNilNode", node, err)
		}
	}
}

func TestDependencyIdentityOverridesContradictingCoordinates(t *testing.T) {
	// Coordinates are the identity's projection, never a second opinion:
	// contradicting name and version are replaced by the identity's split,
	// so presentation and registry seeding cannot disagree with the key.
	node, err := NewDependencyNode(Coordinates{PURL: "pkg:npm/foo@1.0.0", Name: "bar", Version: "2.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if node.NodeID() != "pkg:npm/foo@1.0.0" {
		t.Fatalf("identity = %q", node.NodeID())
	}
	if node.Name != "foo" || node.Version != "1.0.0" {
		t.Fatalf("coordinates still contradict the identity: %s@%s", node.Name, node.Version)
	}
	if pkg := PackageFromDependencyNode(node); pkg.Name != "foo" || pkg.Version != "1.0.0" {
		t.Fatalf("seeded package contradicts the identity: %s@%s", pkg.Name, pkg.Version)
	}
	// An ecosystem-native spelling that re-mints the same identity survives:
	// a Go module keeps its whole path in Name even though the package URL
	// splits the trailing segment off.
	goNode, err := NewDependencyNode(Coordinates{Ecosystem: EcosystemGo, Name: "github.com/example/lib/v2", Version: "v2.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	// Coordinates project from the identity, which splits a Go module path
	// at its trailing segment; the ecosystem-native form comes back through
	// the accessors, which is what external lookups must use (ADR-0021).
	if got := goNode.EcosystemName(); got != "github.com/example/lib/v2" {
		t.Fatalf("EcosystemName() = %q, want the rejoined module path", got)
	}
}

func TestDependencyFromPURLResolvesDirectEcosystemTypes(t *testing.T) {
	// Direct purl types (npm, apk, …) are absent from the type→ecosystem
	// table by design; without the alias lookup a node built from a bare
	// package URL would carry no ecosystem and lose ecosystem-specific
	// behavior — the npm scope in EcosystemName(), for one.
	cases := map[string]struct {
		ecosystem Ecosystem
		name      string
	}{
		"pkg:npm/%40scope/name@1.0.0":     {EcosystemNPM, "@scope/name"},
		"pkg:apk/alpine/musl@1.2.5":       {Ecosystem("apk"), "musl"},
		"pkg:golang/example.com/m@v1.0.0": {EcosystemGo, "example.com/m"},
	}
	for raw, want := range cases {
		node, err := NewDependencyNodeFromPURL(raw)
		if err != nil {
			t.Fatalf("NewDependencyNodeFromPURL(%q): %v", raw, err)
		}
		if node.Ecosystem != want.ecosystem {
			t.Errorf("%s: ecosystem = %q, want %q", raw, node.Ecosystem, want.ecosystem)
		}
		if got := node.EcosystemName(); got != want.name {
			t.Errorf("%s: EcosystemName() = %q, want %q", raw, got, want.name)
		}
	}
}

func TestStructuralNodesAreNotDependencyHops(t *testing.T) {
	// manifest → module → dependency is a direct dependency of that module:
	// structural nodes are not hops, so the manifest projection must not
	// turn direct dependencies into transitive ones.
	manifest := mustManifest(t, "package.json")
	module := mustModule(t, "package.json", Coordinates{Name: "app"})
	direct := mustDepPURL(t, "pkg:npm/left-pad@1.3.0")
	transitive := mustDepPURL(t, "pkg:npm/deep@2.0.0")
	graph := New()
	for _, node := range []GraphNode{manifest, module, direct, transitive} {
		if err := graph.AddNode(node); err != nil {
			t.Fatal(err)
		}
	}
	for _, edge := range [][2]string{
		{manifest.NodeID(), module.NodeID()},
		{module.NodeID(), direct.NodeID()},
		{direct.NodeID(), transitive.NodeID()},
	} {
		if err := graph.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatal(err)
		}
	}
	if got := RelationshipForPath([]GraphNode{manifest, module, direct}); got != DependencyRelationshipDirect {
		t.Fatalf("path relationship = %q, want direct", got)
	}
	if got := RelationshipForPath([]GraphNode{manifest, module, direct, transitive}); got != DependencyRelationshipTransitive {
		t.Fatalf("nested path relationship = %q, want transitive", got)
	}
	relationships := dependencyRelationshipsForGraph(graph)
	if relationships[direct.NodeID()] != DependencyRelationshipDirect {
		t.Fatalf("graph-derived relationship for the module's own dependency = %q, want direct", relationships[direct.NodeID()])
	}
	if relationships[transitive.NodeID()] != DependencyRelationshipTransitive {
		t.Fatalf("graph-derived nested relationship = %q, want transitive", relationships[transitive.NodeID()])
	}
}

func TestManifestFileKindSurvivesTheWire(t *testing.T) {
	manifest, err := NewManifestNode("pom.xml", ManifestKindPackageJSON)
	if err != nil {
		t.Fatal(err)
	}
	graph := New()
	if err := graph.AddNode(manifest); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(graph)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Graph
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	node, ok := decoded.Node(manifest.NodeID())
	if !ok {
		t.Fatal("manifest node lost")
	}
	if got := node.(*ManifestNode).FileKind; got != ManifestKindPackageJSON {
		t.Fatalf("manifest kind = %q, want it to survive the round trip", got)
	}
}

func TestPackageCloneAndMergeCarryDetectedOrigins(t *testing.T) {
	origin := DependencyOrigin{ArtifactURL: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}
	repo := DependencyOrigin{Repository: "https://github.com/left-pad/left-pad"}
	pkg := &Package{Coordinates: Coordinates{PURL: "pkg:npm/left-pad@1.3.0"}, DetectedOrigins: []DependencyOrigin{origin}}
	clone := pkg.Clone()
	clone.DetectedOrigins[0] = repo
	if pkg.DetectedOrigins[0] != origin {
		t.Fatal("Clone shares the detected-origins backing array")
	}
	// Merge unions rather than dropping: a package seeded from two nodes
	// keeps every vetted origin regardless of seeding order.
	target := &Package{Coordinates: Coordinates{PURL: "pkg:npm/left-pad@1.3.0"}, DetectedOrigins: []DependencyOrigin{origin}}
	target.MergeFrom(&Package{DetectedOrigins: []DependencyOrigin{origin, repo}})
	if len(target.DetectedOrigins) != 2 {
		t.Fatalf("MergeFrom detected origins = %+v, want the deduplicated union", target.DetectedOrigins)
	}
}

func TestScopeFilterAppliesToUnattachedDependencies(t *testing.T) {
	// Roots are not a rescue: in an edgeless graph every node has no
	// incoming edge, so seeding the allow-set from Roots() would return the
	// graph unfiltered and hand a runtime caller the development
	// dependencies too. Only structural nodes are retained by kind.
	graph := New()
	module := mustModule(t, "package.json", Coordinates{Name: "app"})
	runtimeDep := mustDepPURL(t, "pkg:npm/react@18.2.0")
	runtimeDep.Scopes = ScopesOf(ScopeRuntime)
	devDep := mustDepPURL(t, "pkg:npm/vitest@2.0.0")
	devDep.Scopes = ScopesOf(ScopeDevelopment)
	orphanDev := mustDepPURL(t, "pkg:npm/orphan@1.0.0")
	orphanDev.Scopes = ScopesOf(ScopeDevelopment)
	for _, node := range []GraphNode{module, runtimeDep, devDep, orphanDev} {
		if err := graph.AddNode(node); err != nil {
			t.Fatal(err)
		}
	}

	filtered, err := FilterGraphByScope(graph, ScopeRuntime)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := filtered.Node(devDep.NodeID()); ok {
		t.Error("edgeless graph: development dependency survived a runtime filter")
	}
	if _, ok := filtered.Node(orphanDev.NodeID()); ok {
		t.Error("orphan development dependency survived a runtime filter")
	}
	if _, ok := filtered.Node(runtimeDep.NodeID()); !ok {
		t.Error("runtime dependency was dropped")
	}
	if _, ok := filtered.Node(module.NodeID()); !ok {
		t.Error("structural module node must be retained by kind")
	}
}

func TestRelationshipDepthDoesNotResetBelowADependency(t *testing.T) {
	// A structural node beneath a dependency does not reset the depth: the
	// dependency under it stays transitive, even though the chain passes
	// through a module node.
	graph := New()
	module := mustModule(t, "package.json", Coordinates{Name: "app"})
	direct := mustDepPURL(t, "pkg:npm/direct@1.0.0")
	nested := mustModule(t, "vendor/package.json", Coordinates{Name: "vendored"})
	deep := mustDepPURL(t, "pkg:npm/deep@1.0.0")
	for _, node := range []GraphNode{module, direct, nested, deep} {
		if err := graph.AddNode(node); err != nil {
			t.Fatal(err)
		}
	}
	for _, edge := range [][2]string{
		{module.NodeID(), direct.NodeID()},
		{direct.NodeID(), nested.NodeID()},
		{nested.NodeID(), deep.NodeID()},
	} {
		if err := graph.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatal(err)
		}
	}
	relationships := dependencyRelationshipsForGraph(graph)
	if relationships[direct.NodeID()] != DependencyRelationshipDirect {
		t.Fatalf("module's own dependency = %q, want direct", relationships[direct.NodeID()])
	}
	if relationships[deep.NodeID()] != DependencyRelationshipTransitive {
		t.Fatalf("dependency below a dependency = %q, want transitive", relationships[deep.NodeID()])
	}
}

func TestModuleRejectsAssertedInvalidPURL(t *testing.T) {
	// An explicitly asserted package URL is a claim the constructor must
	// honor or refuse — never replace with a fabricated one. Both the
	// unparseable and the profile-invalid cases fail, matching the
	// dependency gate.
	for _, asserted := range []string{"not-a-purl", "pkg:maven/commons-text@1.10.0"} {
		if node, err := NewModuleNode("package.json", Coordinates{PURL: asserted, Name: "app"}); err == nil {
			t.Errorf("NewModuleNode(%q) = %q, want rejection", asserted, node.NodeID())
		}
	}
	// A module with no asserted package URL still falls back to path and
	// name, and a valid assertion is honored.
	if node, err := NewModuleNode("package.json", Coordinates{Name: "app"}); err != nil || node.NodeID() != "module:package.json#app" {
		t.Fatalf("path fallback = %v, %v", node, err)
	}
	node, err := NewModuleNode("package.json", Coordinates{PURL: "pkg:npm/app@1.0.0"})
	if err != nil || node.PURL() != "pkg:npm/app@1.0.0" {
		t.Fatalf("valid assertion = %v, %v", node, err)
	}
}

func TestEcosystemProjectsFromTheIdentity(t *testing.T) {
	// A contradicting ecosystem cannot survive: it would seed the registry
	// package into the wrong family and take the wrong name handling.
	node, err := NewDependencyNode(Coordinates{PURL: "pkg:npm/foo@1.0.0", Ecosystem: EcosystemMaven, Name: "foo"})
	if err != nil {
		t.Fatal(err)
	}
	if node.Ecosystem != EcosystemNPM {
		t.Fatalf("ecosystem = %q, want the identity's npm", node.Ecosystem)
	}
	if pkg := PackageFromDependencyNode(node); pkg.Ecosystem != EcosystemNPM {
		t.Fatalf("seeded package ecosystem = %q, want npm", pkg.Ecosystem)
	}
	// A custom purl type resolves to no known ecosystem, so a detector's
	// own token survives — the open vocabulary keeps its say.
	custom, err := NewDependencyNode(Coordinates{PURL: "pkg:pokemon/pikachu@25", Ecosystem: Ecosystem("pokemon"), Name: "pikachu"})
	if err != nil {
		t.Fatal(err)
	}
	if custom.Ecosystem != Ecosystem("pokemon") {
		t.Fatalf("custom ecosystem token = %q, want it preserved", custom.Ecosystem)
	}
}
