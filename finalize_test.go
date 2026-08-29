package sdk

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk/identitykit"
)

func identityTestNode(origin *DependencyOrigin, resolvedURL string) Dependency {
	return Dependency{
		Coordinates: Coordinates{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM, Name: "left-pad", Version: "1.3.0"},
		Origin:      origin,
		ResolvedURL: resolvedURL,
	}
}

func singleEntryContainer(t *testing.T, nodes ...Dependency) *GraphContainer {
	t.Helper()
	graph := New()
	for i := range nodes {
		if _, err := graph.InsertOccurrence(NewDependency(nodes[i])); err != nil {
			t.Fatalf("insert fixture node %d: %v", i, err)
		}
	}
	return SingleGraphContainer(graph, ManifestMetadata{Path: "package-lock.json"})
}

func TestInsertOccurrenceFoldsSameResolutionScopes(t *testing.T) {
	graph := New()
	first := NewDependency(identityTestNode(ArtifactOrigin("https://e.com/a.tgz"), ""))
	first.Scopes = ScopesOf(ScopeRuntime)
	inserted, err := graph.InsertOccurrence(first)
	if err != nil {
		t.Fatal(err)
	}
	repeat := NewDependency(identityTestNode(ArtifactOrigin("https://e.com/a.tgz"), ""))
	repeat.Scopes = ScopesOf(ScopeDevelopment)
	survivor, err := graph.InsertOccurrence(repeat)
	if err != nil {
		t.Fatal(err)
	}
	if survivor != inserted {
		t.Fatal("same-resolution witness minted a new node instead of folding")
	}
	if !survivor.HasScope(ScopeRuntime) || !survivor.HasScope(ScopeDevelopment) {
		t.Fatalf("folded witness lost scopes: %v", survivor.Scopes)
	}
	if graph.Size() != 1 || graph.HasEphemeralOccurrences() {
		t.Fatalf("graph state after fold: size=%d ephemeral=%v", graph.Size(), graph.HasEphemeralOccurrences())
	}
}

func TestInsertOccurrenceKeepsContradictingRecordsAlive(t *testing.T) {
	graph := New()
	if _, err := graph.InsertOccurrence(NewDependency(identityTestNode(ArtifactOrigin("https://e.com/a.tgz"), ""))); err != nil {
		t.Fatal(err)
	}
	second, err := graph.InsertOccurrence(NewDependency(identityTestNode(ArtifactOrigin("https://mirror.e.com/a.tgz"), "")))
	if err != nil {
		t.Fatal(err)
	}
	if !identitykit.IsEphemeralID(second.ID) {
		t.Fatalf("contradicting record ID = %q, want an ephemeral discriminator", second.ID)
	}
	if !graph.HasEphemeralOccurrences() {
		t.Fatal("HasEphemeralOccurrences() = false with a live discriminator")
	}
	// A third witness of the second resolution folds into it rather than
	// minting another discriminator.
	third, err := graph.InsertOccurrence(NewDependency(identityTestNode(ArtifactOrigin("https://mirror.e.com/a.tgz"), "")))
	if err != nil {
		t.Fatal(err)
	}
	if third != second || graph.Size() != 2 {
		t.Fatalf("repeated sibling witness did not fold: size=%d", graph.Size())
	}
}

func TestFinalizeContradictingOriginsGetHashSuffixes(t *testing.T) {
	container := singleEntryContainer(t,
		identityTestNode(ArtifactOrigin("https://e.com/a.tgz"), ""),
		identityTestNode(ArtifactOrigin("https://mirror.e.com/a.tgz"), ""),
	)
	if _, err := FinalizeGraphIdentity(container); err != nil {
		t.Fatal(err)
	}
	graph := container.Entries[0].Graph
	if graph.Size() != 2 {
		t.Fatalf("size = %d, want two occurrences", graph.Size())
	}
	addresses := map[string]struct{}{}
	for _, node := range graph.Nodes() {
		base, suffix := identitykit.SplitID(node.ID)
		if base != "pkg:npm/left-pad@1.3.0" || len(suffix) != 12 {
			t.Fatalf("finalized ID %q, want a hash-suffixed canonical base", node.ID)
		}
		if node.OccurrenceFacet() == "" || !strings.HasPrefix(node.OccurrenceFacet(), "artifact\x00") {
			t.Fatalf("occurrence facet = %q", node.OccurrenceFacet())
		}
		if suffix != identitykit.OccurrenceSuffix(node.OccurrenceFacet()) {
			t.Fatalf("suffix %q does not re-derive from the facet", suffix)
		}
		if node.PURL != "pkg:npm/left-pad@1.3.0" {
			t.Fatalf("canonical PURL not published on the node: %q", node.PURL)
		}
		addresses[node.ContentAddress()] = struct{}{}
	}
	if len(addresses) != 2 {
		t.Fatalf("distinct origins share a content address: %v", addresses)
	}
	if graph.HasEphemeralOccurrences() {
		t.Fatal("ephemeral discriminator survived finalization")
	}
}

func TestFinalizeSameOriginAcrossEntriesSharesID(t *testing.T) {
	shared := ArtifactOrigin("https://e.com/a.tgz")
	entryGraph := func(origin *DependencyOrigin) *Graph {
		g := New()
		if err := g.AddNode(NewDependency(identityTestNode(origin, ""))); err != nil {
			t.Fatal(err)
		}
		return g
	}
	container := &GraphContainer{Entries: []GraphEntry{
		{Graph: entryGraph(shared), Manifest: ManifestMetadata{Path: "a/package-lock.json"}},
		{Graph: entryGraph(shared), Manifest: ManifestMetadata{Path: "b/package-lock.json"}},
		{Graph: entryGraph(ArtifactOrigin("https://mirror.e.com/a.tgz")), Manifest: ManifestMetadata{Path: "c/package-lock.json"}},
	}}
	if _, err := FinalizeGraphIdentity(container); err != nil {
		t.Fatal(err)
	}
	idOf := func(i int) string {
		nodes := container.Entries[i].Graph.Nodes()
		if len(nodes) != 1 {
			t.Fatalf("entry %d has %d nodes", i, len(nodes))
		}
		return nodes[0].ID
	}
	if idOf(0) != idOf(1) {
		t.Fatalf("same origin finalized to different IDs: %q vs %q", idOf(0), idOf(1))
	}
	if idOf(0) == idOf(2) {
		t.Fatalf("contradicting origins share ID %q", idOf(0))
	}
	// The scan-global agreement is what lets the merge fold exactly the
	// witnesses of one resolution.
	merged, err := container.ConsolidatedGraph()
	if err != nil {
		t.Fatal(err)
	}
	if merged.Size() != 2 {
		t.Fatalf("merged size = %d, want the two occurrences", merged.Size())
	}
}

func TestFinalizeProjectOwnedKeepsCanonicalSlot(t *testing.T) {
	project := identityTestNode(ArtifactOrigin("https://e.com/a.tgz"), "")
	project.FirstParty = true
	external := identityTestNode(ArtifactOrigin("https://mirror.e.com/a.tgz"), "")
	// External record inserted first: the canonical slot still ends up with
	// the project record, whatever the traversal order.
	container := singleEntryContainer(t, external, project)
	if _, err := FinalizeGraphIdentity(container); err != nil {
		t.Fatal(err)
	}
	graph := container.Entries[0].Graph
	canonical, ok := graph.Node("pkg:npm/left-pad@1.3.0")
	if !ok || !canonical.FirstParty {
		t.Fatalf("canonical slot holds %+v, want the project record", canonical)
	}
	if canonical.OccurrenceFacet() != FirstPartyOccurrenceFacet {
		t.Fatalf("project facet = %q, want the first-party sentinel", canonical.OccurrenceFacet())
	}
	for _, node := range graph.Nodes() {
		if node.FirstParty {
			continue
		}
		if _, suffix := identitykit.SplitID(node.ID); len(suffix) != 12 {
			t.Fatalf("external record ID %q, want a hash suffix", node.ID)
		}
	}
}

func TestFinalizeGapWitnessFoldsIntoOriginRecord(t *testing.T) {
	witness := identityTestNode(nil, "")
	witness.Scopes = ScopesOf(ScopeDevelopment)
	witness.Locations = []PackageLocation{{RealPath: "package.json"}}
	origin := identityTestNode(ArtifactOrigin("https://e.com/a.tgz"), "")
	origin.Scopes = ScopesOf(ScopeRuntime)
	container := singleEntryContainer(t, origin, witness)
	if _, err := FinalizeGraphIdentity(container); err != nil {
		t.Fatal(err)
	}
	graph := container.Entries[0].Graph
	if graph.Size() != 1 {
		t.Fatalf("size = %d, want the gap witness folded", graph.Size())
	}
	survivor := graph.Nodes()[0]
	if survivor.ID != "pkg:npm/left-pad@1.3.0" || survivor.Origin.Empty() {
		t.Fatalf("survivor = %q origin empty=%v", survivor.ID, survivor.Origin.Empty())
	}
	if !survivor.HasScope(ScopeDevelopment) || !survivor.HasScope(ScopeRuntime) {
		t.Fatalf("fold lost scopes: %v", survivor.Scopes)
	}
	if len(survivor.Locations) != 1 || survivor.Locations[0].RealPath != "package.json" {
		t.Fatalf("fold lost locations: %+v", survivor.Locations)
	}
}

func TestFinalizeRawEvidenceGetsDeterministicOrdinals(t *testing.T) {
	container := singleEntryContainer(t,
		identityTestNode(nil, "registry+https://b.example/left-pad"),
		identityTestNode(nil, "registry+https://a.example/left-pad"),
	)
	if _, err := FinalizeGraphIdentity(container); err != nil {
		t.Fatal(err)
	}
	graph := container.Entries[0].Graph
	first, ok := graph.Node("pkg:npm/left-pad@1.3.0 o1")
	if !ok {
		t.Fatalf("missing o1; nodes: %v", idsOf(graph.Nodes()))
	}
	// Ordinals follow the lexicographic order of the resolution keys, never
	// insertion order: the a.example record sorts first.
	if first.ResolvedURL != "registry+https://a.example/left-pad" {
		t.Fatalf("o1 holds %q, want the lexicographically first key", first.ResolvedURL)
	}
	if _, ok := graph.Node("pkg:npm/left-pad@1.3.0 o2"); !ok {
		t.Fatalf("missing o2; nodes: %v", idsOf(graph.Nodes()))
	}
	for _, node := range graph.Nodes() {
		if node.OccurrenceFacet() != "" {
			t.Fatalf("raw-evidence record carries facet %q", node.OccurrenceFacet())
		}
		if strings.Contains(node.ID, "example") {
			t.Fatalf("raw evidence reached the readable ID: %q", node.ID)
		}
	}
}

func TestFinalizeCoincidingFacetsShareAddressButNotIDs(t *testing.T) {
	// Two records whose resolutions differ (origin key vs raw evidence) but
	// whose admitted identity facets coincide after query stripping: the
	// ordinal keeps their readable IDs apart while they share the
	// stable-facet content address, as the ADR states.
	clean := identityTestNode(ArtifactOrigin("https://e.com/download.tgz"), "")
	tokenized := identityTestNode(
		&DependencyOrigin{ArtifactURL: "https://e.com/download.tgz?artifact=b"},
		"https://e.com/download.tgz?artifact=b",
	)
	container := singleEntryContainer(t, clean, tokenized)
	if _, err := FinalizeGraphIdentity(container); err != nil {
		t.Fatal(err)
	}
	graph := container.Entries[0].Graph
	if graph.Size() != 2 {
		t.Fatalf("size = %d, want two occurrences", graph.Size())
	}
	nodes := graph.Nodes()
	if nodes[0].ContentAddress() != nodes[1].ContentAddress() {
		t.Fatal("coinciding facets must share the stable-facet content address")
	}
	if nodes[0].ID == nodes[1].ID {
		t.Fatal("coinciding facets must keep distinct readable IDs")
	}
	for _, node := range nodes {
		if _, suffix := identitykit.SplitID(node.ID); !strings.HasPrefix(suffix, "o") {
			t.Fatalf("coinciding facet record ID %q, want an ordinal suffix", node.ID)
		}
		if node.OccurrenceFacet() != "artifact\x00https://e.com/download.tgz" {
			t.Fatalf("facet = %q, want the shared stripped facet", node.OccurrenceFacet())
		}
	}
}

func TestFinalizeStripsCredentialBytesEverywhere(t *testing.T) {
	tokenized := identityTestNode(
		&DependencyOrigin{ArtifactURL: "https://e.com/dl.tgz?X-Amz-Signature=secret123"},
		"https://e.com/dl.tgz?X-Amz-Signature=secret123",
	)
	container := singleEntryContainer(t,
		identityTestNode(ArtifactOrigin("https://mirror.e.com/dl.tgz"), ""),
		tokenized,
	)
	if _, err := FinalizeGraphIdentity(container); err != nil {
		t.Fatal(err)
	}
	for _, node := range container.Entries[0].Graph.Nodes() {
		if strings.Contains(node.ID, "secret123") || strings.Contains(node.OccurrenceFacet(), "secret123") {
			t.Fatalf("credential bytes reached identity state: id=%q facet=%q", node.ID, node.OccurrenceFacet())
		}
	}
}

func TestFinalizeIsIdempotentAndReportsRenames(t *testing.T) {
	graph := New()
	root := NewDependency(Dependency{Coordinates: Coordinates{Type: PackageTypeApplication, Name: "app", FirstParty: true}})
	if err := graph.AddNode(root); err != nil {
		t.Fatal(err)
	}
	first, err := graph.InsertOccurrence(NewDependency(identityTestNode(ArtifactOrigin("https://e.com/a.tgz"), "")))
	if err != nil {
		t.Fatal(err)
	}
	second, err := graph.InsertOccurrence(NewDependency(identityTestNode(ArtifactOrigin("https://mirror.e.com/a.tgz"), "")))
	if err != nil {
		t.Fatal(err)
	}
	for _, child := range []*Dependency{first, second} {
		if err := graph.AddEdge(root.ID, child.ID); err != nil {
			t.Fatal(err)
		}
	}
	container := SingleGraphContainer(graph, ManifestMetadata{Path: "package-lock.json"})

	finalization, err := FinalizeGraphIdentity(container)
	if err != nil {
		t.Fatal(err)
	}
	if len(finalization.Renames) != 1 || finalization.Renames[0] == nil {
		t.Fatalf("renames = %+v, want one entry map", finalization.Renames)
	}
	if renamed, ok := finalization.Renames[0][second.ID]; !ok || identitykit.IsEphemeralID(renamed) {
		t.Fatalf("ephemeral record rename missing or still ephemeral: %q", renamed)
	}
	// Edges follow the renames.
	finalGraph := container.Entries[0].Graph
	rootFinal, ok := finalGraph.Node(root.PackageIdentity())
	if !ok {
		t.Fatalf("root lost; nodes: %v", idsOf(finalGraph.Nodes()))
	}
	children, err := finalGraph.DirectDependencies(rootFinal.ID)
	if err != nil || len(children) != 2 {
		t.Fatalf("root edges after finalize: %v, %v", idsOf(children), err)
	}

	before, err := json.Marshal(container.Entries[0].Graph)
	if err != nil {
		t.Fatal(err)
	}
	again, err := FinalizeGraphIdentity(container)
	if err != nil {
		t.Fatal(err)
	}
	if again.Renames[0] != nil {
		t.Fatalf("second finalization renamed nodes: %+v", again.Renames[0])
	}
	after, err := json.Marshal(container.Entries[0].Graph)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("finalization is not idempotent:\nbefore: %s\nafter:  %s", before, after)
	}
}

func TestFinalizeNilAndEmptyContainers(t *testing.T) {
	if _, err := FinalizeGraphIdentity(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := FinalizeGraphIdentity(&GraphContainer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := FinalizeGraphIdentity(&GraphContainer{Entries: []GraphEntry{{}}}); err != nil {
		t.Fatal(err)
	}
}
