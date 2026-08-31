package sdk

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestDocumentIdentityAcceptsABOMLink pins the reason Identity is held to the
// IRI rule rather than the web-URL rule. A CycloneDX BOM-Link is a URN, and
// it is exactly the identifier ADR-0037's merged export links back to -- so
// the web gate would reject the one value this field exists to carry.
func TestDocumentIdentityAcceptsABOMLink(t *testing.T) {
	for _, identity := range []string{
		"urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1",
		"https://example.test/spdxdocs/app-1.0.0-abc123", // an SPDX namespace
	} {
		got, ok := DocumentAssertions{Identity: identity}.Normalized()
		if !ok || got.Identity != identity {
			t.Errorf("identity %q normalized to %q (ok=%v)", identity, got.Identity, ok)
		}
	}
}

// TestDocumentFieldsAreGatedIndependently pins that one unusable field does
// not discard the rest. Dropping the whole record because a data license was
// malformed would lose the link a merged export needs.
func TestDocumentFieldsAreGatedIndependently(t *testing.T) {
	got, ok := DocumentAssertions{
		Identity:    "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1",
		DataLicense: "not a license expression at all",
		Name:        "app SBOM",
	}.Normalized()
	if !ok {
		t.Fatal("a record with one bad field was dropped entirely")
	}
	if got.Identity == "" || got.Name == "" {
		t.Errorf("a bad data license took the good fields with it: %+v", got)
	}
	if got.DataLicense != "" {
		t.Errorf("an unparseable data license survived as %q", got.DataLicense)
	}
}

// TestDocumentDataLicenseRefusesAMintedRef pins that a document's data license
// cannot be a LicenseRef. Its extracted text would have nowhere to live, so a
// consumer reading the field as an SPDX expression could not resolve it.
func TestDocumentDataLicenseRefusesAMintedRef(t *testing.T) {
	got, _ := DocumentAssertions{DataLicense: "LicenseRef-custom-thing"}.Normalized()
	if got.DataLicense != "" {
		t.Errorf("a minted LicenseRef survived as the data license: %q", got.DataLicense)
	}
	// A spec-listed identifier still works, so this refuses the ref rather
	// than the field.
	listed, _ := DocumentAssertions{DataLicense: "CC0-1.0"}.Normalized()
	if listed.DataLicense == "" {
		t.Error("a spec-listed data license was refused")
	}
}

// TestDocumentAssertionsRejectUnpublishableValues pins the gates on each
// free-text field, since these are written back into a document.
func TestDocumentAssertionsRejectUnpublishableValues(t *testing.T) {
	long := strings.Repeat("a", maxDocumentFieldLength+1)
	got, _ := DocumentAssertions{
		Identity: "not an iri with spaces",
		Name:     long,
		Created:  "2024-01-01T00:00:00Z\nCreator: injected",
		Comment:  long,
	}.Normalized()
	if got.Identity != "" {
		t.Errorf("a malformed identity survived as %q", got.Identity)
	}
	if got.Name != "" || got.Comment != "" {
		t.Errorf("an over-long field survived: name=%d comment=%d", len(got.Name), len(got.Comment))
	}
	if got.Created != "" {
		t.Errorf("a timestamp carrying a newline survived as %q; SPDX's tag form is line-oriented", got.Created)
	}
}

// TestDocumentToolsNeedAName pins that a version with nothing to attach it to
// is dropped rather than written as a nameless tool.
func TestDocumentToolsNeedAName(t *testing.T) {
	got, _ := DocumentAssertions{
		Tools: []DocumentTool{
			{Version: "1.0.0"},                // no name
			{Name: "bomly", Version: "0.6.0"}, // kept
			{Name: "x\ty", Version: "1"},      // control character
			{Name: strings.Repeat("n", 5000)}, // over the limit
		},
	}.Normalized()
	if len(got.Tools) != 1 || got.Tools[0].Name != "bomly" {
		t.Errorf("tools = %+v, want only the named one", got.Tools)
	}
}

// TestDocumentAssertionsAreSorted pins that a document built from these is
// byte-stable across runs that read the same values in a different order.
func TestDocumentAssertionsAreSorted(t *testing.T) {
	a, _ := DocumentAssertions{
		Creators: []Contact{{Kind: ContactKindOrganization, Name: "Zeta"}, {Kind: ContactKindOrganization, Name: "Alpha"}},
		Tools:    []DocumentTool{{Name: "zzz"}, {Name: "aaa"}},
	}.Normalized()
	b, _ := DocumentAssertions{
		Creators: []Contact{{Kind: ContactKindOrganization, Name: "Alpha"}, {Kind: ContactKindOrganization, Name: "Zeta"}},
		Tools:    []DocumentTool{{Name: "aaa"}, {Name: "zzz"}},
	}.Normalized()
	if a.Creators[0].Name != "Alpha" || a.Tools[0].Name != "aaa" {
		t.Errorf("not sorted: creators=%+v tools=%+v", a.Creators, a.Tools)
	}
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	if string(left) != string(right) {
		t.Errorf("order changed the bytes:\n%s\n%s", left, right)
	}
}

// TestMergeDocumentAssertions pins the two merge rules and the gate on the way
// in.
func TestMergeDocumentAssertions(t *testing.T) {
	left := DocumentAssertions{
		Identity: "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1",
		Name:     "first",
		Creators: []Contact{{Kind: ContactKindOrganization, Name: "Acme"}},
		Tools:    []DocumentTool{{Name: "bomly", Version: "0.6.0"}},
	}
	right := DocumentAssertions{
		Identity: "urn:cdx:00000000-0000-0000-0000-000000000000/1",
		Name:     "second",
		Created:  "2024-01-01T00:00:00Z",
		Creators: []Contact{{Kind: ContactKindOrganization, Name: "Other"}},
		Tools:    []DocumentTool{{Name: "bomly", Version: "0.6.0"}, {Name: "syft"}},
	}
	merged := MergeDocumentAssertions(left, right)

	// Scalars fill gaps only: a stated value is not overwritten...
	if merged.Identity != left.Identity || merged.Name != "first" {
		t.Errorf("a stated scalar was overwritten: %+v", merged)
	}
	// ... and a gap is filled.
	if merged.Created != "2024-01-01T00:00:00Z" {
		t.Errorf("a gap was not filled: %q", merged.Created)
	}
	// Lists union and deduplicate.
	if len(merged.Creators) != 2 {
		t.Errorf("creators = %+v, want both", merged.Creators)
	}
	if len(merged.Tools) != 2 {
		t.Errorf("tools = %+v, want the union with the duplicate collapsed", merged.Tools)
	}

	// Both sides are gated on the way in: an unpublishable value must not
	// become visible just because it arrived through a merge.
	dirty := MergeDocumentAssertions(
		DocumentAssertions{},
		DocumentAssertions{Identity: "not an iri", Name: strings.Repeat("a", maxDocumentFieldLength+1)},
	)
	if dirty.Identity != "" || dirty.Name != "" {
		t.Errorf("a merge admitted an ungated value: %+v", dirty)
	}
}

// TestMergeIsOrderIndependentForLists pins that two entries merged in either
// order credit the same creators and tools, so a merged document does not
// depend on which source was read first.
func TestMergeIsOrderIndependentForLists(t *testing.T) {
	a := DocumentAssertions{Creators: []Contact{{Kind: ContactKindOrganization, Name: "Acme"}}}
	b := DocumentAssertions{Creators: []Contact{{Kind: ContactKindOrganization, Name: "Other"}}}
	left, _ := json.Marshal(MergeDocumentAssertions(a, b).Creators)
	right, _ := json.Marshal(MergeDocumentAssertions(b, a).Creators)
	if string(left) != string(right) {
		t.Errorf("merge order changed the credited creators:\n%s\n%s", left, right)
	}
}

// TestGraphEntryDocumentIsOmitEmpty pins that an entry with no source document
// writes the exact bytes it wrote before the field existed.
func TestGraphEntryDocumentIsOmitEmpty(t *testing.T) {
	data, err := json.Marshal(GraphEntry{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := decoded["document"]; present {
		t.Error("an entry with no document wrote the field")
	}
}

// TestIndexNodesByPackageIsDerived pins that the reverse index is a view and
// not a second home for a stored fact. The registry keeps packages keyed by
// PURL and nothing about where they were found; the nodes keep PackageRef.
func TestIndexNodesByPackageIsDerived(t *testing.T) {
	g := New()
	first, err := NewDependencyNode(Coordinates{Name: "left-pad", Version: "1.3.0", Ecosystem: EcosystemNPM})
	if err != nil {
		t.Fatalf("NewDependencyNode: %v", err)
	}
	second, err := NewDependencyNode(Coordinates{Name: "right-pad", Version: "2.0.0", Ecosystem: EcosystemNPM})
	if err != nil {
		t.Fatalf("NewDependencyNode: %v", err)
	}
	unmatched, err := NewDependencyNode(Coordinates{Name: "no-match", Version: "1.0.0", Ecosystem: EcosystemNPM})
	if err != nil {
		t.Fatalf("NewDependencyNode: %v", err)
	}
	first.PackageRef = "pkg:npm/left-pad@1.3.0"
	second.PackageRef = "pkg:npm/left-pad@1.3.0" // same package, two nodes
	for _, node := range []*DependencyNode{first, second, unmatched} {
		if err := g.AddNode(node); err != nil {
			t.Fatalf("AddNode: %v", err)
		}
	}

	index := IndexNodesByPackage(g)
	nodes := index.Nodes("pkg:npm/left-pad@1.3.0")
	if len(nodes) != 2 {
		t.Fatalf("index gave %d nodes, want 2", len(nodes))
	}
	if nodes[0].NodeID() > nodes[1].NodeID() {
		t.Error("the index is not ordered by node ID, so iteration is unstable")
	}
	// A node with no package reference is not indexed under "".
	if got := index.Nodes(""); len(got) != 0 {
		t.Errorf(`unmatched nodes were indexed under "": %d`, len(got))
	}
	// It is a view: removing a node and rebuilding reflects the graph, and the
	// stale index is simply discarded.
	g.RemoveNode(second.NodeID())
	if again := IndexNodesByPackage(g).Nodes("pkg:npm/left-pad@1.3.0"); len(again) != 1 {
		t.Errorf("rebuilt index gave %d nodes, want 1", len(again))
	}
	if len(index.Nodes("pkg:npm/left-pad@1.3.0")) != 2 {
		t.Error("the old index changed under the caller; it is meant to be a snapshot")
	}
}

// TestIndexUsagesJoinsAcrossNodes pins the reason the index earns its place: a
// vulnerability names a package, and the question is about every node that
// package resolved to.
func TestIndexUsagesJoinsAcrossNodes(t *testing.T) {
	g := New()
	web := workspaceNode(t)
	web.PackageRef = "pkg:npm/left-pad@1.3.0"
	if err := g.AddNode(web); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	index := IndexNodesByPackage(g)
	evidence := []ReachabilityEvidence{{ModuleRoot: "apps/api", Status: ReachabilityReachable}}

	got := index.Usages("pkg:npm/left-pad@1.3.0", evidence, UsageFilter{Reachable: true, Scope: ScopeRuntime})
	if len(got) != 1 || got[0].ModuleRoot != "apps/api" {
		t.Errorf("usages = %+v, want only apps/api", got)
	}
	// A package nothing resolved to has no usages, rather than every usage.
	if got := index.Usages("pkg:npm/absent@1.0.0", evidence, UsageFilter{}); len(got) != 0 {
		t.Errorf("an unknown package gave %d usages", len(got))
	}
}
