package sdk

import (
	"encoding/json"
	"strconv"
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

// A merged SPDX export names its sources through externalDocumentRefs, and
// SPDX 2.3 requires a checksum on every one -- so without a checksum on the
// carrier the export could not link its sources at all. The digest is
// captured at ingest while the bytes are in hand; the version rides beside
// it because a BOM-Link needs it and SPDX records it.
func TestDocumentVersionAndChecksumAreGatedAndFillGaps(t *testing.T) {
	good := DocumentAssertions{
		Identity: "https://example.test/spdxdocs/app",
		Version:  2,
		Checksum: &Digest{Algorithm: "SHA-256", Value: "  d1e8a70b5ccab1dc2f56bbf7e99f064a660c08e361a35751b9c483c88943d082  "},
	}
	normalized, ok := good.Normalized()
	if !ok {
		t.Fatal("a document with a version and checksum was rejected")
	}
	if normalized.Version != 2 {
		t.Errorf("Version = %d, want 2", normalized.Version)
	}
	if normalized.Checksum == nil || normalized.Checksum.Algorithm != DigestAlgorithmSHA256 ||
		normalized.Checksum.Value != "d1e8a70b5ccab1dc2f56bbf7e99f064a660c08e361a35751b9c483c88943d082" {
		t.Errorf("Checksum = %+v, want the digest gate's canonical form", normalized.Checksum)
	}

	// The gates: a non-positive version is not one a document stated, and
	// an unpublishable digest is dropped whole rather than carried as a zero
	// record. Each field is independent of the others, as the rest are.
	for name, bad := range map[string]DocumentAssertions{
		"zero version":      {Identity: good.Identity, Version: 0},
		"negative version":  {Identity: good.Identity, Version: -1},
		"unknown algorithm": {Identity: good.Identity, Checksum: &Digest{Algorithm: "CRC32", Value: "abcd"}},
		"empty value":       {Identity: good.Identity, Checksum: &Digest{Algorithm: "SHA-256", Value: "   "}},
		"value with space":  {Identity: good.Identity, Checksum: &Digest{Algorithm: "SHA-256", Value: "ab cd"}},
		// A valid digest of the wrong object: a source-tree or metadata hash
		// is not a hash of the document's bytes, and the SPDX reference has
		// no slot to say which it was.
		"source-tree subject": {Identity: good.Identity, Checksum: &Digest{Algorithm: "SHA-256", Value: good.Checksum.Value, Subject: DigestSubjectSourceTree}},
		"metadata subject":    {Identity: good.Identity, Checksum: &Digest{Algorithm: "SHA-256", Value: good.Checksum.Value, Subject: DigestSubjectMetadata}},
	} {
		got, ok := bad.Normalized()
		if !ok || got.Identity != good.Identity {
			t.Errorf("%s: the identity was lost with the bad field: ok=%v %+v", name, ok, got)
		}
		if got.Version != 0 || got.Checksum != nil {
			t.Errorf("%s: an ungated value survived: version=%d checksum=%+v", name, got.Version, got.Checksum)
		}
	}

	// A BOM-Link identity names its version in the tail, and a stated
	// version that disagrees with it is a self-contradiction: the identity
	// wins and the version is dropped. An agreeing one is kept, and an SPDX
	// namespace carries no version to disagree with.
	bomLink := "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1"
	for name, tc := range map[string]struct {
		in   DocumentAssertions
		want int
	}{
		"bom-link agrees":    {DocumentAssertions{Identity: bomLink, Version: 1}, 1},
		"bom-link disagrees": {DocumentAssertions{Identity: bomLink, Version: 2}, 0},
		"bom-link unstated":  {DocumentAssertions{Identity: bomLink}, 0},
		"spdx namespace":     {DocumentAssertions{Identity: good.Identity, Version: 2}, 2},
	} {
		got, _ := tc.in.Normalized()
		if got.Version != tc.want || got.Identity != tc.in.Identity {
			t.Errorf("%s: version = %d, identity = %q; want %d and the identity kept", name, got.Version, got.Identity, tc.want)
		}
	}

	// A checksum alone is a publishable record: it is the field the SPDX
	// link cannot do without.
	if _, ok := (DocumentAssertions{Checksum: good.Checksum}).Normalized(); !ok {
		t.Error("a document carrying only a checksum was reported empty")
	}

	// Merge class: fill-gaps, as one provenance tuple with the identity. A
	// stated tuple stands...
	other := DocumentAssertions{
		Identity: good.Identity,
		Version:  7,
		Checksum: &Digest{Algorithm: "SHA-1", Value: "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
	}
	merged := MergeDocumentAssertions(good, other)
	if merged.Version != 2 || merged.Checksum == nil || merged.Checksum.Algorithm != DigestAlgorithmSHA256 {
		t.Errorf("a stated version or checksum was overwritten: %+v %+v", merged.Version, merged.Checksum)
	}
	// ... the same document seen twice fills its own gaps...
	filled := MergeDocumentAssertions(DocumentAssertions{Identity: good.Identity}, other)
	if filled.Version != 7 || filled.Checksum == nil || filled.Checksum.Algorithm != DigestAlgorithmSHA1 {
		t.Errorf("a gap was not filled for the same document: %+v %+v", filled.Version, filled.Checksum)
	}
	// ... a side with no link at all takes the other's whole tuple...
	whole := MergeDocumentAssertions(DocumentAssertions{Name: "unlinked"}, other)
	if whole.Identity != good.Identity || whole.Version != 7 || whole.Checksum == nil || whole.Name != "unlinked" {
		t.Errorf("a record with no link did not take the tuple whole: %+v", whole)
	}
	// ... and two different documents never mix: A's identity must not be
	// paired with B's version or checksum, or an SPDX external-document
	// reference would claim A's bytes have B's checksum.
	documentB := DocumentAssertions{
		Identity: "https://example.test/spdxdocs/other",
		Version:  3,
		Checksum: &Digest{Algorithm: "SHA-1", Value: "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
	}
	mixed := MergeDocumentAssertions(DocumentAssertions{Identity: good.Identity}, documentB)
	if mixed.Identity != good.Identity || mixed.Version != 0 || mixed.Checksum != nil {
		t.Errorf("document B's link fields were attached to document A: %+v", mixed)
	}
	// The same identity at two stated versions is two documents too: version
	// 1 must not take version 2's hash.
	conflict := MergeDocumentAssertions(
		DocumentAssertions{Identity: good.Identity, Version: 1},
		DocumentAssertions{Identity: good.Identity, Version: 2, Checksum: documentB.Checksum},
	)
	if conflict.Version != 1 || conflict.Checksum != nil {
		t.Errorf("a version conflict let the other version's checksum through: %+v", conflict)
	}
	// The merge does not alias its inputs.
	filled.Checksum.Value = "changed"
	if other.Checksum.Value == "changed" {
		t.Error("the merged checksum aliases the source digest")
	}

	// Clone is deep for the pointer too.
	clone := normalized.Clone()
	clone.Checksum.Value = "changed"
	if normalized.Checksum.Value == "changed" {
		t.Error("Clone aliased the checksum")
	}
}

// The gates run in the codec on both directions, so no call site can bypass
// them: a payload from a plugin, or a hand-built value marshaled without
// Normalized, is held to the same rules. Before the hooks existed a negative
// version and an invalid identity decoded unchanged, and a checksum the digest
// codec had zeroed re-encoded as "checksum":{} -- a non-nil record an exporter
// would read as a checksum being present.
func TestDocumentAssertionsCodecAppliesTheGates(t *testing.T) {
	payload := `{"identity":"not an iri","name":"x\ny","created":"2024-01-01T00:00:00Z",` +
		`"version":-3,"checksum":{"algorithm":"CRC32","value":"abcd"}}`
	var decoded DocumentAssertions
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Identity != "" || decoded.Name != "" || decoded.Version != 0 || decoded.Checksum != nil {
		t.Fatalf("ungated values survived decode: %+v", decoded)
	}
	if decoded.Created != "2024-01-01T00:00:00Z" {
		t.Fatalf("a good field was lost alongside the bad ones: %+v", decoded)
	}

	// The same on the way out, for a value that never passed Normalized.
	dirty := DocumentAssertions{
		Identity: "https://example.test/spdxdocs/app",
		Version:  -1,
		Checksum: &Digest{Algorithm: "CRC32", Value: "abcd"},
	}
	data, err := json.Marshal(dirty)
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"version", "checksum"} {
		if _, present := keys[field]; present {
			t.Errorf("an ungated %q was written: %s", field, data)
		}
	}
	if _, present := keys["identity"]; !present {
		t.Errorf("the good identity was lost: %s", data)
	}

	// A gated record round-trips exactly.
	good, _ := DocumentAssertions{
		Identity: "https://example.test/spdxdocs/app", Version: 2,
		Checksum: &Digest{Algorithm: "SHA-256", Value: "d1e8a70b5ccab1dc2f56bbf7e99f064a660c08e361a35751b9c483c88943d082"},
	}.Normalized()
	data, err = json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	var again DocumentAssertions
	if err := json.Unmarshal(data, &again); err != nil {
		t.Fatal(err)
	}
	if again.Version != 2 || again.Checksum == nil || *again.Checksum != *good.Checksum || again.Identity != good.Identity {
		t.Fatalf("round trip changed the record: %+v -> %+v", good, again)
	}
}

// A merged export writes one link per source document, and until this field
// existed those links were write-only: ingest had nowhere to put them, so a
// merged inventory lost every trace of its inputs after one round trip.
func TestDocumentSourcesAreGatedAndUnion(t *testing.T) {
	self := "https://example.test/spdxdocs/merged"
	a := "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1"
	b := "https://example.test/spdxdocs/b"
	doc := DocumentAssertions{
		Identity: self,
		Sources: []string{
			b, " " + a + " ", b, // unsorted, padded, duplicated
			self,          // a document is not built from itself
			"not an iri",  // fails the identity gate
			"file:///etc", // a local path is not a link a document can publish
		},
	}
	got, ok := doc.Normalized()
	if !ok {
		t.Fatal("a document with sources was rejected")
	}
	if want := []string{b, a}; !equalStrings(got.Sources, want) {
		t.Fatalf("Sources = %v, want %v: gated, deduplicated, self dropped, sorted", got.Sources, want)
	}
	// The bound is a count on the gated list.
	many := make([]string, 0, maxDocumentSources+10)
	for i := 0; i < maxDocumentSources+10; i++ {
		many = append(many, "https://example.test/spdxdocs/src-"+strconv.Itoa(i))
	}
	bounded, _ := DocumentAssertions{Sources: many}.Normalized()
	if len(bounded.Sources) != maxDocumentSources {
		t.Fatalf("len(Sources) = %d, want the bound %d", len(bounded.Sources), maxDocumentSources)
	}
	// Sources alone are a publishable record.
	if _, ok := (DocumentAssertions{Sources: []string{a}}).Normalized(); !ok {
		t.Error("a document carrying only sources was reported empty")
	}

	// Merge class: set, unioned by value, and the merged record's own
	// identity never lands among its sources. Each side is gated first, so
	// a side's own identity is already out of its list; which identity the
	// merged record keeps decides what drops from the union.
	left := DocumentAssertions{Identity: self, Sources: []string{a}}
	right := DocumentAssertions{Identity: b, Sources: []string{b, self}}
	one := MergeDocumentAssertions(left, right)
	if !equalStrings(one.Sources, []string{a}) {
		// Keeps self as identity, so self drops from the union; b was
		// right's identity, never a source.
		t.Errorf("merged sources = %v, want %v", one.Sources, []string{a})
	}
	two := MergeDocumentAssertions(right, left)
	if !equalStrings(two.Sources, []string{self, a}) {
		// Keeps b as identity, so self is a legitimate source here.
		t.Errorf("merged (other order) sources = %v, want %v", two.Sources, []string{self, a})
	}

	// Through the codec, gated on both directions.
	data, err := json.Marshal(DocumentAssertions{Identity: self, Sources: []string{self, "not an iri", a}})
	if err != nil {
		t.Fatal(err)
	}
	var decoded DocumentAssertions
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !equalStrings(decoded.Sources, []string{a}) {
		t.Errorf("sources after the codec = %v, want only the publishable link", decoded.Sources)
	}
	// Clone does not alias.
	clone := got.Clone()
	clone.Sources[0] = "changed"
	if got.Sources[0] == "changed" {
		t.Error("Clone aliased the sources")
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
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

	// The additive fields on the document itself vanish when unstated, so a
	// document that never stated a version or checksum writes the exact
	// bytes it wrote before the fields existed -- which is also why an
	// unstated version is zero here and not the format default of one.
	data, err = json.Marshal(DocumentAssertions{Identity: "https://example.test/spdxdocs/app"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, field := range []string{"version", "checksum", "sources"} {
		if _, present := decoded[field]; present {
			t.Errorf("an unstated %q was written to the wire", field)
		}
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
