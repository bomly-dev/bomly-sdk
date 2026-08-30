package sdk

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestLocatorKindComesFromThePair pins that the shape is derived from the
// (category, type) pair, never from the category alone. SECURITY holds both
// CPE values and advisory URLs; PACKAGE-MANAGER holds both package URLs and
// bare coordinates. A category-only rule would validate half of them wrongly.
func TestLocatorKindComesFromThePair(t *testing.T) {
	for _, tc := range []struct {
		category ExternalReferenceCategory
		refType  string
		want     LocatorKind
	}{
		{ExternalReferenceCategorySecurity, "cpe23Type", LocatorKindCPE},
		{ExternalReferenceCategorySecurity, "cpe22Type", LocatorKindCPE},
		{ExternalReferenceCategorySecurity, "advisory", LocatorKindURL},
		{ExternalReferenceCategorySecurity, "fix", LocatorKindURL},
		{ExternalReferenceCategorySecurity, "swid", LocatorKindIdentifier},
		{ExternalReferenceCategoryPackageManager, "purl", LocatorKindPURL},
		{ExternalReferenceCategoryPackageManager, "maven-central", LocatorKindIdentifier},
		{ExternalReferenceCategoryPersistentID, "gitoid", LocatorKindIdentifier},
		// SPDX OTHER, and any type added after this table was written, take
		// the form that asserts the least.
		{ExternalReferenceCategoryOther, "anything", LocatorKindIdentifier},
		{ExternalReferenceCategorySecurity, "invented-later", LocatorKindIdentifier},
		// No category means the reference came from CycloneDX, whose schema
		// types the field as an IRI reference.
		{ExternalReferenceCategoryUnknown, "website", LocatorKindURL},
		{ExternalReferenceCategoryUnknown, "vcs", LocatorKindURL},
		// The type vocabulary is compared case-insensitively.
		{ExternalReferenceCategorySecurity, "CPE23TYPE", LocatorKindCPE},
	} {
		if got := LocatorKindFor(tc.category, tc.refType); got != tc.want {
			t.Errorf("LocatorKindFor(%q, %q) = %q, want %q", tc.category, tc.refType, got, tc.want)
		}
	}
}

// TestExternalReferenceValidatesByItsDeclaredKind pins that each locator is
// held to the grammar its pair names -- and, just as importantly, that a
// locator failing its declared grammar is rejected rather than quietly
// reclassified as something it would pass.
func TestExternalReferenceValidatesByItsDeclaredKind(t *testing.T) {
	for _, tc := range []struct {
		name      string
		reference ExternalReference
		want      bool
	}{
		{
			name:      "a package URL locator",
			reference: ExternalReference{Category: ExternalReferenceCategoryPackageManager, Type: "purl", Locator: "pkg:npm/left-pad@1.3.0"},
			want:      true,
		},
		{
			name:      "a URL where a package URL is declared",
			reference: ExternalReference{Category: ExternalReferenceCategoryPackageManager, Type: "purl", Locator: "https://npmjs.test/left-pad"},
			want:      false,
		},
		{
			// Parses as a package URL, but maven requires a namespace. The
			// locator is held to the same profile rules a dependency
			// identity is, not merely to purl syntax.
			name:      "a package URL that violates its type profile",
			reference: ExternalReference{Category: ExternalReferenceCategoryPackageManager, Type: "purl", Locator: "pkg:maven/tomcat@9.0"},
			want:      false,
		},
		{
			name:      "the same coordinate with its namespace",
			reference: ExternalReference{Category: ExternalReferenceCategoryPackageManager, Type: "purl", Locator: "pkg:maven/org.apache.tomcat/tomcat@9.0"},
			want:      true,
		},
		{
			name:      "a CPE 2.3 formatted string",
			reference: ExternalReference{Category: ExternalReferenceCategorySecurity, Type: "cpe23Type", Locator: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
			want:      true,
		},
		{
			name:      "a CPE 2.2 URI",
			reference: ExternalReference{Category: ExternalReferenceCategorySecurity, Type: "cpe22Type", Locator: "cpe:/a:vendor:product:1.0"},
			want:      true,
		},
		{
			name:      "a truncated CPE",
			reference: ExternalReference{Category: ExternalReferenceCategorySecurity, Type: "cpe23Type", Locator: "cpe:2.3:a:vendor"},
			want:      false,
		},
		{
			name:      "an advisory URL",
			reference: ExternalReference{Category: ExternalReferenceCategorySecurity, Type: "advisory", Locator: "https://advisories.test/GHSA-1234"},
			want:      true,
		},
		{
			name:      "an advisory URL carrying credentials",
			reference: ExternalReference{Category: ExternalReferenceCategorySecurity, Type: "advisory", Locator: "https://user:pw@advisories.test/x"},
			want:      false,
		},
		{
			name:      "a maven coordinate, which is not a URL",
			reference: ExternalReference{Category: ExternalReferenceCategoryPackageManager, Type: "maven-central", Locator: "org.apache.tomcat:tomcat:9.0.0.M4"},
			want:      true,
		},
		{
			name:      "an identifier carrying whitespace",
			reference: ExternalReference{Category: ExternalReferenceCategoryOther, Type: "other", Locator: "two tokens"},
			want:      false,
		},
		{
			name:      "a CycloneDX website reference",
			reference: ExternalReference{Type: "website", Locator: "https://example.test"},
			want:      true,
		},
		{
			name:      "a reference with no locator at all",
			reference: ExternalReference{Type: "website"},
			want:      false,
		},
	} {
		_, ok := tc.reference.Normalized()
		if ok != tc.want {
			t.Errorf("%s: Normalized ok = %v, want %v", tc.name, ok, tc.want)
		}
	}
}

// TestExternalReferenceMergeIdentityIsTheTriple pins what counts as one
// reference. The same locator under two types is two assertions -- "this is
// the source repository" and "this is where advisories live" say different
// things -- so the type is part of the identity.
func TestExternalReferenceMergeIdentityIsTheTriple(t *testing.T) {
	merged := MergeExternalReferences(
		[]ExternalReference{{Type: "vcs", Locator: "https://git.test/owner/repo"}},
		[]ExternalReference{
			{Type: "vcs", Locator: "https://git.test/owner/repo", Comment: "the repository"},
			{Type: "issue-tracker", Locator: "https://git.test/owner/repo"},
		},
	)
	if len(merged) != 2 {
		t.Fatalf("merged = %+v, want the two distinct assertions", merged)
	}
	// The repeated triple folded, and its comment filled the gap.
	for _, reference := range merged {
		if reference.Type == "vcs" && reference.Comment != "the repository" {
			t.Fatalf("the repeated reference did not take the later comment: %+v", reference)
		}
	}
}

// TestExternalReferenceMergeIsOrderIndependent pins that a set built from the
// same references in different orders publishes the same document.
// Consolidation folds witnesses in whatever order they arrive.
func TestExternalReferenceMergeIsOrderIndependent(t *testing.T) {
	a := ExternalReference{Type: "website", Locator: "https://example.test/a"}
	b := ExternalReference{Category: ExternalReferenceCategorySecurity, Type: "advisory", Locator: "https://example.test/b"}
	c := ExternalReference{Category: ExternalReferenceCategoryPackageManager, Type: "purl", Locator: "pkg:npm/left-pad@1.3.0"}

	first := MergeExternalReferences([]ExternalReference{a, b, c}, nil)
	second := MergeExternalReferences([]ExternalReference{c, a}, []ExternalReference{b})
	if len(first) != len(second) {
		t.Fatalf("orders produced %d and %d references", len(first), len(second))
	}
	for i := range first {
		if first[i].referenceKey() != second[i].referenceKey() {
			t.Fatalf("order changed the result: %+v vs %+v", first, second)
		}
	}
}

// TestExternalReferenceHashesAreGated pins that a reference's own integrity
// claims are held to the digest rules, and that a rejected one does not
// survive as an empty object inside the encoded array.
func TestExternalReferenceHashesAreGated(t *testing.T) {
	reference := ExternalReference{
		Type:    "distribution",
		Locator: "https://cdn.test/pkg.tgz",
		Hashes: []Digest{
			{Algorithm: "SHA-256", Value: "abc"}, // a foreign spelling
			{Algorithm: "crc32", Value: "zz"},    // unpublishable
		},
	}
	normalized, ok := reference.Normalized()
	if !ok {
		t.Fatal("a valid reference was rejected")
	}
	if len(normalized.Hashes) != 1 || normalized.Hashes[0].Algorithm != DigestAlgorithmSHA256 {
		t.Fatalf("hashes = %+v, want the spelling normalized and the reject dropped", normalized.Hashes)
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if strings.Contains(string(encoded), "{}") {
		t.Fatalf("a rejected hash survived as an empty object: %s", encoded)
	}
}

// TestExternalReferencesTravelWithTheComponent pins that references survive
// the wire and reach the registry, and that the decoder holds an arriving
// payload to the same rules the encoder does.
func TestExternalReferencesTravelWithTheComponent(t *testing.T) {
	graph := New()
	node := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "react", Version: "18.2.0"})
	node.ExternalReferences = []ExternalReference{
		{Type: "website", Locator: "https://react.test"},
		{Category: ExternalReferenceCategorySecurity, Type: "cpe23Type", Locator: "cpe:2.3:a:meta:react:18.2.0:*:*:*:*:*:*:*"},
	}
	if err := graph.AddNode(node); err != nil {
		t.Fatalf("add node: %v", err)
	}
	encoded, err := json.Marshal(graph)
	if err != nil {
		t.Fatalf("encode graph: %v", err)
	}
	var decoded Graph
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("decode graph: %v", err)
	}
	round := decoded.DependencyNodes()[0]
	if len(round.ExternalReferences) != 2 {
		t.Fatalf("references did not survive the wire: %+v", round.ExternalReferences)
	}
	if seeded := PackageFromDependencyNode(round).ExternalReferences; len(seeded) != 2 {
		t.Fatalf("references did not reach the registry: %+v", seeded)
	}

	// An arriving payload is gated: a purl-declared locator that is a URL is
	// not a package URL, and the reference points at nothing without it.
	payload := `{"nodes":[{"kind":"dependency","id":"pkg:npm/a@1.0.0","purl":"pkg:npm/a@1.0.0","external_references":[` +
		`{"category":"package-manager","type":"purl","locator":"https://npmjs.test/a"},` +
		`{"type":"website","locator":"https://user:pw@a.test/"}]}]}`
	var gated Graph
	if err := json.Unmarshal([]byte(payload), &gated); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if got := gated.DependencyNodes()[0].ExternalReferences; len(got) != 0 {
		t.Fatalf("unpublishable references survived the decoder: %+v", got)
	}
}

// TestExternalReferenceFoldUnionsWitnesses pins that folding two witnesses
// keeps every reference either recorded.
func TestExternalReferenceFoldUnionsWitnesses(t *testing.T) {
	graph := New()
	first := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "b", Version: "1.0.0"})
	first.ExternalReferences = []ExternalReference{{Type: "website", Locator: "https://b.test"}}
	if err := graph.AddNode(first); err != nil {
		t.Fatalf("add first: %v", err)
	}
	second := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "b", Version: "1.0.0"})
	second.ExternalReferences = []ExternalReference{{Type: "vcs", Locator: "https://git.test/b"}}
	if _, err := graph.InsertNode(second); err != nil {
		t.Fatalf("insert second: %v", err)
	}
	if got := graph.DependencyNodes()[0].ExternalReferences; len(got) != 2 {
		t.Fatalf("fold kept %+v, want both witnesses' references", got)
	}
}

// TestParseExternalReferenceCategory pins the SPDX axis, including that its
// own spelling round-trips.
func TestParseExternalReferenceCategory(t *testing.T) {
	for spelling, want := range map[string]ExternalReferenceCategory{
		"SECURITY":        ExternalReferenceCategorySecurity,
		"security":        ExternalReferenceCategorySecurity,
		"PACKAGE-MANAGER": ExternalReferenceCategoryPackageManager,
		"PACKAGE_MANAGER": ExternalReferenceCategoryPackageManager,
		"PERSISTENT-ID":   ExternalReferenceCategoryPersistentID,
		"OTHER":           ExternalReferenceCategoryOther,
		"":                ExternalReferenceCategoryUnknown,
	} {
		got, err := ParseExternalReferenceCategory(spelling)
		if err != nil || got != want {
			t.Errorf("ParseExternalReferenceCategory(%q) = %q, %v; want %q", spelling, got, err, want)
		}
	}
	if _, err := ParseExternalReferenceCategory("invented"); err == nil {
		t.Error("an unrecognized category was accepted")
	}
	// Bounded before it is lowercased, as the other vocabularies are.
	_, err := ParseExternalReferenceCategory(strings.Repeat("x", maxVocabularyTokenLength+1))
	if err == nil || !strings.Contains(err.Error(), "over the") {
		t.Errorf("error = %v, want the length bound to have rejected it", err)
	}
	// Every declared category has an SPDX spelling; unknown deliberately
	// does not, since it means the source had no such axis.
	for _, category := range []ExternalReferenceCategory{
		ExternalReferenceCategorySecurity, ExternalReferenceCategoryPackageManager,
		ExternalReferenceCategoryPersistentID, ExternalReferenceCategoryOther,
	} {
		if category.SPDXName() == "" {
			t.Errorf("category %q has no SPDX spelling", category)
		}
	}
	if ExternalReferenceCategoryUnknown.SPDXName() != "" {
		t.Error("the unknown category reported an SPDX spelling")
	}
}

// TestExternalReferenceRefusesMalformedCategoryAndType pins that neither axis
// is silently emptied. Both carry meaning: an empty category says the source
// had no such axis (CycloneDX), and the type decides which grammar the
// locator is held to as well as being part of the merge identity. Clearing
// either would rewrite the source's assertion rather than reject it.
func TestExternalReferenceRefusesMalformedCategoryAndType(t *testing.T) {
	for _, tc := range []struct {
		name      string
		reference ExternalReference
	}{
		{
			name:      "a misspelled category",
			reference: ExternalReference{Category: "SECURTY", Type: "advisory", Locator: "https://advisories.test/x"},
		},
		{
			name:      "a type carrying whitespace",
			reference: ExternalReference{Category: ExternalReferenceCategorySecurity, Type: "advisory link", Locator: "https://advisories.test/x"},
		},
		{
			name:      "no type at all",
			reference: ExternalReference{Locator: "https://example.test"},
		},
		{
			name:      "an oversized type",
			reference: ExternalReference{Type: strings.Repeat("x", maxReferenceTypeLength+1), Locator: "https://example.test"},
		},
	} {
		if got, ok := tc.reference.Normalized(); ok {
			t.Errorf("%s: accepted as %+v, want the reference refused", tc.name, got)
		}
	}
}

// TestKnownReferenceTypesAreCanonicalized pins that a recognized type reaches
// the document in the specification's spelling. The vocabulary compares
// case-insensitively, so two spellings are one reference — without this,
// which spelling was published would depend on which witness folded first.
func TestKnownReferenceTypesAreCanonicalized(t *testing.T) {
	normalized, ok := ExternalReference{
		Category: ExternalReferenceCategorySecurity,
		Type:     "CPE23TYPE",
		Locator:  "cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*",
	}.Normalized()
	if !ok {
		t.Fatal("a valid reference was rejected")
	}
	if normalized.Type != "cpe23Type" {
		t.Fatalf("type = %q, want the specification's own spelling", normalized.Type)
	}
	// An unrecognized type is carried as given: the vocabulary is open, so a
	// type this build does not know is not a type to correct.
	custom, ok := ExternalReference{Type: "Some-Future-Type", Locator: "https://example.test"}.Normalized()
	if !ok || custom.Type != "Some-Future-Type" {
		t.Fatalf("custom type normalized to %+v, want it carried unchanged", custom)
	}
}

// TestCPELocatorValidatesThePartComponent pins the check that neither
// available CPE library performs. See isCPELocator for the probe results:
// nvdtools accepts these, and umisama/go-cpe rewrites them into valid-looking
// values, which is worse.
func TestCPELocatorValidatesThePartComponent(t *testing.T) {
	for _, locator := range []string{
		"cpe:2.3:x:vendor:product:1.0:*:*:*:*:*:*:*", // part "x" is not defined
		"cpe:/aardvark", // part is not a part
		"cpe:/x:v:p",
		"cpe:2.3:a:vendor", // truncated
	} {
		reference := ExternalReference{Category: ExternalReferenceCategorySecurity, Type: "cpe23Type", Locator: locator}
		if got, ok := reference.Normalized(); ok {
			t.Errorf("%q was accepted as a CPE: %+v", locator, got)
		}
	}
	// Every defined part, in both bindings, is accepted.
	for _, locator := range []string{
		"cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*",
		"cpe:2.3:o:v:p:1.0:*:*:*:*:*:*:*",
		"cpe:2.3:h:v:p:1.0:*:*:*:*:*:*:*",
		"cpe:2.3:*:v:p:1.0:*:*:*:*:*:*:*",
		"cpe:/a:vendor:product:1.0",
		"cpe:/o:vendor",
		"cpe:/",
	} {
		reference := ExternalReference{Category: ExternalReferenceCategorySecurity, Type: "cpe22Type", Locator: locator}
		if _, ok := reference.Normalized(); !ok {
			t.Errorf("%q was rejected, but it is a well-formed CPE", locator)
		}
	}
}

// TestMergedReferenceContentIsOrderIndependent pins the two places where
// sorting the reference list cannot help: a comment that differs between two
// witnesses of one reference, and the nested hash array inside it. Both live
// within a single record, so only reconciling them makes the exported
// document independent of the order consolidation folded witnesses in.
func TestMergedReferenceContentIsOrderIndependent(t *testing.T) {
	withZ := ExternalReference{Type: "vcs", Locator: "https://git.test/r", Comment: "z"}
	withA := ExternalReference{Type: "vcs", Locator: "https://git.test/r", Comment: "a"}
	forward := MergeExternalReferences([]ExternalReference{withZ}, []ExternalReference{withA})
	reverse := MergeExternalReferences([]ExternalReference{withA}, []ExternalReference{withZ})
	if len(forward) != 1 || len(reverse) != 1 {
		t.Fatalf("merged to %d and %d records, want one each", len(forward), len(reverse))
	}
	if forward[0].Comment != reverse[0].Comment {
		t.Fatalf("comment depends on order: %q forward, %q reverse", forward[0].Comment, reverse[0].Comment)
	}

	first := ExternalReference{Type: "distribution", Locator: "https://cdn.test/p.tgz",
		Hashes: []Digest{{Algorithm: DigestAlgorithmSHA256, Value: "bbb"}}}
	second := ExternalReference{Type: "distribution", Locator: "https://cdn.test/p.tgz",
		Hashes: []Digest{{Algorithm: DigestAlgorithmSHA1, Value: "aaa"}}}
	forwardHashes := MergeExternalReferences([]ExternalReference{first}, []ExternalReference{second})
	reverseHashes := MergeExternalReferences([]ExternalReference{second}, []ExternalReference{first})
	if len(forwardHashes[0].Hashes) != 2 || len(reverseHashes[0].Hashes) != 2 {
		t.Fatalf("hashes did not union: %+v / %+v", forwardHashes[0].Hashes, reverseHashes[0].Hashes)
	}
	for i := range forwardHashes[0].Hashes {
		if forwardHashes[0].Hashes[i] != reverseHashes[0].Hashes[i] {
			t.Fatalf("nested hash order depends on witness order: %+v vs %+v",
				forwardHashes[0].Hashes, reverseHashes[0].Hashes)
		}
	}
}

// TestClonedReferenceSlicesAreIndependent pins that a clone does not share a
// backing array with its source. A zero-length slice made with spare capacity
// still aliases, so a later append on either side would write into the other.
func TestClonedReferenceSlicesAreIndependent(t *testing.T) {
	original := &Package{ExternalReferences: []ExternalReference{{Type: "website", Locator: "https://a.test"}}}
	clone := original.Clone()
	clone.ExternalReferences[0].Type = "vcs"
	if original.ExternalReferences[0].Type != "website" {
		t.Fatal("editing the clone changed the original package")
	}

	node := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "a", Version: "1.0.0"})
	node.ExternalReferences = []ExternalReference{{
		Type: "distribution", Locator: "https://cdn.test/a.tgz",
		Hashes: []Digest{{Algorithm: DigestAlgorithmSHA256, Value: "abc"}},
	}}
	nodeClone := node.Clone()
	nodeClone.ExternalReferences[0].Hashes[0].Value = "changed"
	if node.ExternalReferences[0].Hashes[0].Value != "abc" {
		t.Fatal("editing the clone's nested hashes changed the original node")
	}
}

// TestLocatorBoundAppliesToTheNormalizedForm pins a break the fuzzer found:
// canonical rendering can make a locator longer than it arrived, so a value
// just under the limit could normalize to one just over it — accepted on
// write and rejected on read. The same shape of defect appeared in
// NormalizeURL, where percent-encoding grows a fragment.
func TestLocatorBoundAppliesToTheNormalizedForm(t *testing.T) {
	// A package URL whose name re-encodes wider than it arrived: canonical
	// rendering percent-encodes "+" as "%2B", tripling those bytes. This is
	// the shape the fuzzer found.
	grows := "pkg:a/" + strings.Repeat("+", 3000)
	if len(grows) > maxLocatorLength {
		t.Fatalf("fixture is %d bytes, want it under the limit before encoding", len(grows))
	}
	reference := ExternalReference{
		Category: ExternalReferenceCategoryPackageManager,
		Type:     "purl",
		Locator:  grows,
	}
	normalized, ok := reference.Normalized()
	if ok && len(normalized.Locator) > maxLocatorLength {
		t.Fatalf("accepted a locator whose normalized form is %d bytes, over the %d byte limit",
			len(normalized.Locator), maxLocatorLength)
	}
	// Whatever is accepted must survive a second pass unchanged.
	if ok {
		again, stillOK := reference.Normalized()
		if !stillOK || again.Locator != normalized.Locator {
			t.Fatalf("normalizing twice changed the locator")
		}
	}
}
