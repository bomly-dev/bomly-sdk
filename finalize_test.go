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

func TestFinalizeIsStableAcrossPluginWireRoundTrip(t *testing.T) {
	// Facets derive only from codec-surviving origin state, so a finalized
	// graph that crosses the JSON plugin boundary re-finalizes to the same
	// IDs, facets, and addresses. The tokenized origin is the sharp case:
	// its query-carrying artifact URL fails ADR-0033 normalization, the
	// codec serializes it empty, and admission must reach the same "no
	// facet" answer before and after the boundary.
	clean := identityTestNode(ArtifactOrigin("https://e.com/download.tgz"), "")
	tokenized := identityTestNode(
		&DependencyOrigin{ArtifactURL: "https://e.com/download.tgz?artifact=b"},
		"https://e.com/download.tgz?artifact=b",
	)
	container := singleEntryContainer(t, clean, tokenized)
	if _, err := FinalizeGraphIdentity(container); err != nil {
		t.Fatal(err)
	}
	snapshot := func(c *GraphContainer) map[string][2]string {
		out := make(map[string][2]string)
		for _, node := range c.Entries[0].Graph.Nodes() {
			out[node.ID] = [2]string{node.OccurrenceFacet(), node.ContentAddress()}
		}
		return out
	}
	before := snapshot(container)
	if len(before) != 2 {
		t.Fatalf("want two occurrences, got %v", before)
	}

	encoded, err := json.Marshal(container.Entries[0].Graph)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Graph
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	roundTripped := SingleGraphContainer(&decoded, ManifestMetadata{Path: "package-lock.json"})
	if _, err := FinalizeGraphIdentity(roundTripped); err != nil {
		t.Fatal(err)
	}
	after := snapshot(roundTripped)
	for id, want := range before {
		got, ok := after[id]
		if !ok {
			t.Fatalf("node %q lost its ID across the wire round trip: %v", id, after)
		}
		// The facet is in-process state and recomputes; the address must
		// re-derive identically from what survived the codec.
		if got != want {
			t.Fatalf("node %q changed across the wire: %v -> %v", id, want, got)
		}
	}
}

func TestResolutionKeyDomainsCannotCollide(t *testing.T) {
	// A raw resolution string spelling the first-party sentinel — or an
	// origin key's NUL-joined form — must not fold an external record into
	// the project record or a structured-origin occurrence: each key
	// variant carries its own domain tag.
	graph := New()
	project := identityTestNode(nil, "")
	project.FirstParty = true
	if _, err := graph.InsertOccurrence(NewDependency(project)); err != nil {
		t.Fatal(err)
	}
	spoofed := identityTestNode(nil, resolutionKeyFirstParty)
	inserted, err := graph.InsertOccurrence(NewDependency(spoofed))
	if err != nil {
		t.Fatal(err)
	}
	if !identitykit.IsEphemeralID(inserted.ID) {
		t.Fatalf("sentinel-spoofing raw record folded into the project record: %q", inserted.ID)
	}
	origin := ArtifactOrigin("https://e.com/a.tgz").Normalized()
	rawSpoof := identityTestNode(nil, origin.ArtifactURL+"\x00"+origin.Repository+"\x00"+origin.Revision)
	structured := identityTestNode(ArtifactOrigin("https://e.com/a.tgz"), "")
	if resolutionKey(NewDependency(rawSpoof)) == resolutionKey(NewDependency(structured)) {
		t.Fatal("raw origin-key spelling collides with the structured origin key")
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

	// Marshal order is insertion order, so idempotence compares the sorted
	// identity snapshot rather than raw bytes.
	before := graphIdentitySnapshot(container.Entries[0].Graph)
	again, err := FinalizeGraphIdentity(container)
	if err != nil {
		t.Fatal(err)
	}
	if again.Renames[0] != nil {
		t.Fatalf("second finalization renamed nodes: %+v", again.Renames[0])
	}
	if after := graphIdentitySnapshot(container.Entries[0].Graph); before != after {
		t.Fatalf("finalization is not idempotent:\nbefore: %s\nafter:  %s", before, after)
	}
}

func TestImportedApplicationComponentsAreNotProjectOwned(t *testing.T) {
	// Ownership is the FirstParty marker, never the package type (the
	// NodeIsEnrichable rule): two application-typed components imported from
	// an SBOM with contradicting resolutions are distinct external
	// occurrences — folding them under a shared first-party key would lose a
	// contradiction.
	imported := func(url string) Dependency {
		return Dependency{
			Coordinates: Coordinates{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM, Type: PackageTypeApplication, Name: "left-pad", Version: "1.3.0"},
			Origin:      ArtifactOrigin(url),
		}
	}
	if (&Dependency{Coordinates: Coordinates{Type: PackageTypeApplication}}).ProjectOwned() {
		t.Fatal("application type alone must not read as project-owned")
	}
	container := singleEntryContainer(t,
		imported("https://e.com/a.tgz"),
		imported("https://mirror.e.com/a.tgz"),
	)
	if _, err := FinalizeGraphIdentity(container); err != nil {
		t.Fatal(err)
	}
	graph := container.Entries[0].Graph
	if graph.Size() != 2 {
		t.Fatalf("size = %d — the contradicting imported occurrences folded", graph.Size())
	}
	for _, node := range graph.Nodes() {
		if node.OccurrenceFacet() == FirstPartyOccurrenceFacet {
			t.Fatalf("imported component %q carries the first-party sentinel", node.ID)
		}
		if _, suffix := identitykit.SplitID(node.ID); len(suffix) != 12 {
			t.Fatalf("imported component ID %q, want an external hash suffix", node.ID)
		}
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

func TestFoldPreservesFirstPartyOwnership(t *testing.T) {
	// The evidence-free witness arrives first and holds the plain base; the
	// project's own record folds into it at finalization. Ownership is a
	// positive assertion and must survive the fold regardless of insertion
	// or sort order.
	witness := identityTestNode(nil, "")
	project := identityTestNode(nil, "")
	project.FirstParty = true
	container := singleEntryContainer(t, witness, project)
	if _, err := FinalizeGraphIdentity(container); err != nil {
		t.Fatal(err)
	}
	graph := container.Entries[0].Graph
	if graph.Size() != 1 {
		t.Fatalf("size = %d, want the witnesses folded", graph.Size())
	}
	if survivor := graph.Nodes()[0]; !survivor.FirstParty {
		t.Fatal("fold dropped the first-party ownership marker")
	}
}

func TestInsertOccurrenceSkipsRemovedOrdinals(t *testing.T) {
	graph := New()
	if _, err := graph.InsertOccurrence(NewDependency(identityTestNode(ArtifactOrigin("https://a.e.com/a.tgz"), ""))); err != nil {
		t.Fatal(err)
	}
	second, err := graph.InsertOccurrence(NewDependency(identityTestNode(ArtifactOrigin("https://b.e.com/a.tgz"), "")))
	if err != nil {
		t.Fatal(err)
	}
	third, err := graph.InsertOccurrence(NewDependency(identityTestNode(ArtifactOrigin("https://c.e.com/a.tgz"), "")))
	if err != nil {
		t.Fatal(err)
	}
	// Removing an earlier sibling must not make the next discriminator
	// collide with a live one: the ordinal clears the highest live sibling.
	if !graph.RemoveNode(second.ID) {
		t.Fatalf("remove %q failed", second.ID)
	}
	fourth, err := graph.InsertOccurrence(NewDependency(identityTestNode(ArtifactOrigin("https://d.e.com/a.tgz"), "")))
	if err != nil {
		t.Fatalf("insert after removal: %v", err)
	}
	if fourth.ID == third.ID || fourth.ID == second.ID {
		t.Fatalf("recycled a discriminator: %q", fourth.ID)
	}
}

func TestFinalizeIDOnlyNodesKeepDistinctStableAddresses(t *testing.T) {
	// Nodes with no derivable package identity keep their supplied ID as the
	// base: distinct custom bases must yield distinct content addresses, and
	// a second finalization must be a fixed point even for their contested,
	// suffixed occurrences.
	graph := New()
	insert := func(id, url string) {
		t.Helper()
		if _, err := graph.InsertOccurrence(NewDependencyWithID(id, Dependency{Origin: ArtifactOrigin(url)})); err != nil {
			t.Fatal(err)
		}
	}
	insert("legacy-custom-id", "https://e.com/a.tgz")
	insert("legacy-custom-id", "https://mirror.e.com/a.tgz")
	insert("other-custom-id", "https://e.com/b.tgz")
	container := SingleGraphContainer(graph, ManifestMetadata{Path: "custom.lock"})
	if _, err := FinalizeGraphIdentity(container); err != nil {
		t.Fatal(err)
	}
	finalized := container.Entries[0].Graph
	if finalized.Size() != 3 {
		t.Fatalf("size = %d, want 3; nodes: %v", finalized.Size(), idsOf(finalized.Nodes()))
	}
	addresses := make(map[string]string)
	for _, node := range finalized.Nodes() {
		if node.ContentAddress() == "" {
			t.Fatalf("node %q has no content address", node.ID)
		}
		if other, dup := addresses[node.ContentAddress()]; dup {
			t.Fatalf("nodes %q and %q share a content address", node.ID, other)
		}
		addresses[node.ContentAddress()] = node.ID
	}
	before := graphIdentitySnapshot(finalized)
	facetsBefore := make(map[string]string)
	for _, node := range finalized.Nodes() {
		facetsBefore[node.ID] = node.OccurrenceFacet()
	}
	if _, err := FinalizeGraphIdentity(container); err != nil {
		t.Fatal(err)
	}
	refinalized := container.Entries[0].Graph
	if after := graphIdentitySnapshot(refinalized); before != after {
		t.Fatalf("ID-only finalization is not a fixed point:\nbefore: %s\nafter:  %s", before, after)
	}
	for _, node := range refinalized.Nodes() {
		if node.OccurrenceFacet() != facetsBefore[node.ID] {
			t.Fatalf("re-finalizing changed %q facet: %q -> %q", node.ID, facetsBefore[node.ID], node.OccurrenceFacet())
		}
	}
}

func TestAuthoredSuffixShapedIDsArePreserved(t *testing.T) {
	// A legacy custom ID that merely looks like a suffixed occurrence
	// ("component o1" beside "component") must keep its bytes: stripping is
	// provenance-gated to tokens finalization itself minted, so authored
	// IDs are never silently renamed or folded into a sibling.
	graph := New()
	for _, id := range []string{"component", "component o1", "component a1b2c3d4e5f6"} {
		if _, err := graph.InsertOccurrence(NewDependencyWithID(id, Dependency{})); err != nil {
			t.Fatal(err)
		}
	}
	container := SingleGraphContainer(graph, ManifestMetadata{Path: "custom.lock"})
	finalization, err := FinalizeGraphIdentity(container)
	if err != nil {
		t.Fatal(err)
	}
	if finalization.Renames[0] != nil {
		t.Fatalf("authored IDs were renamed: %v", finalization.Renames[0])
	}
	finalized := container.Entries[0].Graph
	if finalized.Size() != 3 {
		t.Fatalf("size = %d, want all three authored IDs preserved: %v", finalized.Size(), idsOf(finalized.Nodes()))
	}
	addresses := make(map[string]string)
	for _, node := range finalized.Nodes() {
		if other, dup := addresses[node.ContentAddress()]; dup {
			t.Fatalf("authored IDs %q and %q share a content address", node.ID, other)
		}
		addresses[node.ContentAddress()] = node.ID
	}
}
