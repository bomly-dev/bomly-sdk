package sdk

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	spdxcommon "github.com/spdx/tools-golang/spdx/v2/common"
)

// typedEdgeGraph builds a manifest -> module -> dependency graph and states a
// kind on the first edge that contradicts what derivation would produce.
//
// The contradiction is the point: a derived kind survives any reconstruction
// trivially, because the destination re-derives it from the same nodes. Only a
// stated kind that disagrees with the structure can show that the kind itself
// was carried rather than recomputed.
func typedEdgeGraph(t *testing.T) (g *Graph, manifestID, moduleID, depID string) {
	t.Helper()
	manifest, err := NewManifestNode("package.json", ManifestKindPackageJSON)
	if err != nil {
		t.Fatalf("NewManifestNode: %v", err)
	}
	module, err := NewModuleNode("package.json", Coordinates{Name: "app", Version: "1.0.0", Ecosystem: EcosystemNPM})
	if err != nil {
		t.Fatalf("NewModuleNode: %v", err)
	}
	dep, err := NewDependencyNode(Coordinates{Name: "left-pad", Version: "1.3.0", Ecosystem: EcosystemNPM})
	if err != nil {
		t.Fatalf("NewDependencyNode: %v", err)
	}
	g = New()
	for _, node := range []GraphNode{manifest, module, dep} {
		if err := g.AddNode(node); err != nil {
			t.Fatalf("AddNode: %v", err)
		}
	}
	manifestID, moduleID, depID = manifest.NodeID(), module.NodeID(), dep.NodeID()
	if derived := DeriveEdgeKind(manifest, module); derived != EdgeKindDescribes {
		t.Fatalf("manifest -> module derives %q, want %q; the fixture no longer contradicts", derived, EdgeKindDescribes)
	}
	if err := g.AddTypedEdge(manifestID, moduleID, EdgeKindDependsOn); err != nil {
		t.Fatalf("AddTypedEdge: %v", err)
	}
	if err := g.AddEdge(moduleID, depID); err != nil {
		t.Fatalf("AddEdge: %v", err)
	}
	return g, manifestID, moduleID, depID
}

// TestGraphReconstructionPreservesEdgeKind is the guard the edge-copy
// primitive exists for. Four places rebuild a graph's edges -- the container
// merge, the JSON decoder, the scope filter, and detectorkit's subgraph -- and
// each rebuilt them from (from, to) pairs alone, so every one of them would
// drop a kind. Routing them through CopyEdgesInto gives that rule one home;
// this fails if a site stops using it.
func TestGraphReconstructionPreservesEdgeKind(t *testing.T) {
	t.Run("json round trip", func(t *testing.T) {
		g, manifestID, moduleID, depID := typedEdgeGraph(t)
		encoded, err := json.Marshal(g)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var decoded Graph
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		assertEdgeKinds(t, &decoded, manifestID, moduleID, depID)
	})

	t.Run("container merge", func(t *testing.T) {
		g, manifestID, moduleID, depID := typedEdgeGraph(t)
		dst := New()
		if err := MergeGraph(dst, g); err != nil {
			t.Fatalf("MergeGraph: %v", err)
		}
		assertEdgeKinds(t, dst, manifestID, moduleID, depID)
	})

	t.Run("scope filter", func(t *testing.T) {
		g, manifestID, moduleID, depID := typedEdgeGraph(t)
		// The dependency carries no scope, so filtering on runtime keeps the
		// structural nodes and the edge under test.
		filtered, err := FilterGraphByScope(g, ScopeRuntime)
		if err != nil {
			t.Fatalf("FilterGraphByScope: %v", err)
		}
		if filtered.EdgeKindOf(manifestID, moduleID) != EdgeKindDependsOn {
			t.Errorf("the filtered graph lost the stated kind: %q", filtered.EdgeKindOf(manifestID, moduleID))
		}
		_ = depID
	})
}

func assertEdgeKinds(t *testing.T, g *Graph, manifestID, moduleID, depID string) {
	t.Helper()
	if got := g.EdgeKindOf(manifestID, moduleID); got != EdgeKindDependsOn {
		t.Errorf("stated kind became %q, want %q -- the kind was recomputed, not carried", got, EdgeKindDependsOn)
	}
	if got := g.EdgeKindOf(moduleID, depID); got != EdgeKindDependsOn {
		t.Errorf("derived kind became %q, want %q", got, EdgeKindDependsOn)
	}
}

// TestReconstructionSitesUseTheSharedPrimitive is the source-level half of the
// guard. A behavioral test only covers the sites it knows about; this fails
// when a new one appears, which is how the fourth site got written the wrong
// way in the first place.
func TestReconstructionSitesUseTheSharedPrimitive(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		// WalkEdges discards the kind. Anything rebuilding a graph must use
		// WalkTypedEdges, or CopyEdgesInto which is built on it.
		if strings.Contains(string(source), "WalkEdges(") && name != "graph.go" {
			t.Errorf("%s calls WalkEdges, which drops every edge kind; "+
				"use CopyEdgesInto for a rebuild, or WalkTypedEdges when the kind is needed", name)
		}
	}
}

// TestEdgeKindsProjectToRelationshipsTheLibraryDeclares is the differential
// test for the SPDX side. Bomly produces two relationship types; this fails if
// a spelling it writes stops being one the library declares.
//
// The other direction -- every SPDX relationship having a Bomly kind -- is
// deliberately not asserted. SPDX declares forty-odd types, Bomly consumes
// none of them here, and mapping types nothing produces would be vocabulary
// with no caller to keep it honest.
func TestEdgeKindsProjectToRelationshipsTheLibraryDeclares(t *testing.T) {
	declared := declaredConstants(t, "github.com/spdx/tools-golang/spdx/v2/common", "string")
	if len(declared) == 0 {
		t.Fatal("no constants found; the differential test is not reading the library")
	}
	values := map[string]bool{}
	for _, value := range declared {
		values[value] = true
	}
	for _, kind := range []EdgeKind{EdgeKindDependsOn, EdgeKindDescribes} {
		name := kind.SPDXName()
		if name == "" {
			t.Errorf("%q has no SPDX projection", kind)
			continue
		}
		if !values[name] {
			t.Errorf("%q projects to %q, which tools-golang no longer declares", kind, name)
		}
	}
	// The spellings are the library's, not strings typed here.
	if EdgeKindDependsOn.SPDXName() != spdxcommon.TypeRelationshipDependsOn {
		t.Error("depends-on is not using the library's spelling")
	}
	if EdgeKindDescribes.SPDXName() != spdxcommon.TypeRelationshipDescribe {
		t.Error("describes is not using the library's spelling")
	}
	// An unknown kind projects to nothing, so a caller writes no relationship
	// rather than guessing one.
	if got := EdgeKindUnknown.SPDXName(); got != "" {
		t.Errorf("the unknown kind projected to %q", got)
	}
}

// TestDeriveEdgeKind pins the structural rule: only manifest -> module is
// structural, and everything else is a dependency claim.
func TestDeriveEdgeKind(t *testing.T) {
	manifest, err := NewManifestNode("package.json", ManifestKindPackageJSON)
	if err != nil {
		t.Fatalf("NewManifestNode: %v", err)
	}
	module, err := NewModuleNode("package.json", Coordinates{Name: "app", Version: "1.0.0", Ecosystem: EcosystemNPM})
	if err != nil {
		t.Fatalf("NewModuleNode: %v", err)
	}
	dep, err := NewDependencyNode(Coordinates{Name: "left-pad", Version: "1.3.0", Ecosystem: EcosystemNPM})
	if err != nil {
		t.Fatalf("NewDependencyNode: %v", err)
	}
	cases := []struct {
		name     string
		from, to GraphNode
		want     EdgeKind
	}{
		{"manifest describes module", manifest, module, EdgeKindDescribes},
		{"manifest naming a dependency directly", manifest, dep, EdgeKindDependsOn},
		{"module depends on dependency", module, dep, EdgeKindDependsOn},
		{"dependency depends on dependency", dep, dep, EdgeKindDependsOn},
		{"nil source", nil, dep, EdgeKindUnknown},
		{"nil target", dep, nil, EdgeKindUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DeriveEdgeKind(tc.from, tc.to); got != tc.want {
				t.Errorf("DeriveEdgeKind = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestMergeEdgeKind pins what happens when one edge is claimed twice.
func TestMergeEdgeKind(t *testing.T) {
	cases := []struct {
		current, next, want EdgeKind
	}{
		{EdgeKindUnknown, EdgeKindDependsOn, EdgeKindDependsOn},
		{EdgeKindDependsOn, EdgeKindUnknown, EdgeKindDependsOn},
		{EdgeKindDescribes, EdgeKindDescribes, EdgeKindDescribes},
		// Disagreement resolves to the dependency claim: it is the stronger
		// assertion, and losing it would drop the edge from a dependency-only
		// export.
		{EdgeKindDescribes, EdgeKindDependsOn, EdgeKindDependsOn},
		{EdgeKindDependsOn, EdgeKindDescribes, EdgeKindDependsOn},
		{EdgeKindUnknown, EdgeKindUnknown, EdgeKindUnknown},
	}
	for _, tc := range cases {
		if got := MergeEdgeKind(tc.current, tc.next); got != tc.want {
			t.Errorf("MergeEdgeKind(%q, %q) = %q, want %q", tc.current, tc.next, got, tc.want)
		}
	}
	// Merging is order-independent, or two graphs merged in a different order
	// would disagree about the same edge.
	for _, pair := range [][2]EdgeKind{
		{EdgeKindDescribes, EdgeKindDependsOn},
		{EdgeKindUnknown, EdgeKindDescribes},
	} {
		if a, b := MergeEdgeKind(pair[0], pair[1]), MergeEdgeKind(pair[1], pair[0]); a != b {
			t.Errorf("MergeEdgeKind is order-dependent for %v: %q vs %q", pair, a, b)
		}
	}
}

// TestAddingAnEdgeTwiceKeepsTheStatedKind pins that a second AddEdge does not
// discard a kind an earlier AddTypedEdge stated. The old AddEdge returned
// early on a duplicate, which would have made the outcome depend on call
// order.
func TestAddingAnEdgeTwiceKeepsTheStatedKind(t *testing.T) {
	g, manifestID, moduleID, _ := typedEdgeGraph(t)
	// A bare AddEdge derives "describes" and must not overwrite the stated
	// "depends-on".
	if err := g.AddEdge(manifestID, moduleID); err != nil {
		t.Fatalf("AddEdge: %v", err)
	}
	if got := g.EdgeKindOf(manifestID, moduleID); got != EdgeKindDependsOn {
		t.Errorf("a duplicate AddEdge changed the kind to %q", got)
	}
}

// TestEdgeKindIsWrittenOnlyWhenItContradictsDerivation pins the wire rule that
// let this field be additive: a decoder derives an absent kind, so writing a
// derived value would add bytes that say nothing and would change every
// existing payload.
func TestEdgeKindIsWrittenOnlyWhenItContradictsDerivation(t *testing.T) {
	g, _, moduleID, depID := typedEdgeGraph(t)
	encoded, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var payload struct {
		Edges []DependencyEdge `json:"edges"`
	}
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var stated, derived int
	for _, edge := range payload.Edges {
		if edge.FromID == moduleID && edge.ToID == depID {
			if edge.Kind != EdgeKindUnknown {
				t.Errorf("a derived edge wrote %q, adding bytes that say nothing", edge.Kind)
			}
			derived++
			continue
		}
		if edge.Kind != EdgeKindDependsOn {
			t.Errorf("the contradicting edge wrote %q, so a reader cannot recover it", edge.Kind)
		}
		stated++
	}
	if stated != 1 || derived != 1 {
		t.Fatalf("expected one stated and one derived edge, got %d and %d", stated, derived)
	}
}

// TestParseEdgeKindIsStrict pins that a kind Bomly cannot read fails a decode
// rather than silently becoming a dependency claim.
func TestParseEdgeKindIsStrict(t *testing.T) {
	for _, value := range []string{"contains", "DEPENDS_ON", "depends on", "unknown", strings.Repeat("a", 4096)} {
		if got, err := ParseEdgeKind(value); err == nil {
			t.Errorf("ParseEdgeKind(%q) accepted, giving %q", value, got)
		}
	}
	for value, want := range map[string]EdgeKind{
		"":             EdgeKindUnknown,
		"depends-on":   EdgeKindDependsOn,
		"  Depends-On": EdgeKindDependsOn,
		"describes":    EdgeKindDescribes,
	} {
		got, err := ParseEdgeKind(value)
		if err != nil {
			t.Errorf("ParseEdgeKind(%q) failed: %v", value, err)
			continue
		}
		if got != want {
			t.Errorf("ParseEdgeKind(%q) = %q, want %q", value, got, want)
		}
	}
}
