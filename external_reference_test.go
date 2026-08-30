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
		{ExternalReferenceCategorySecurity, "cpe23Type", LocatorKindCPE23},
		{ExternalReferenceCategorySecurity, "cpe22Type", LocatorKindCPE22},
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
		// types the field as an IRI reference -- a web URL or a BOM-Link,
		// not a web URL only.
		{ExternalReferenceCategoryUnknown, "website", LocatorKindIRI},
		{ExternalReferenceCategoryUnknown, "vcs", LocatorKindIRI},
		// The type vocabulary is compared case-insensitively.
		{ExternalReferenceCategorySecurity, "CPE23TYPE", LocatorKindCPE23},
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
		refType := "cpe23Type"
		if strings.HasPrefix(locator, "cpe:/") {
			refType = "cpe22Type"
		}
		reference := ExternalReference{Category: ExternalReferenceCategorySecurity, Type: refType, Locator: locator}
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
		refType := "cpe22Type"
		if strings.HasPrefix(locator, "cpe:2.3:") {
			refType = "cpe23Type"
		}
		reference := ExternalReference{Category: ExternalReferenceCategorySecurity, Type: refType, Locator: locator}
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

// TestCPEBindingMustMatchItsDeclaredType pins that the declared type decides
// which binding is validated. A single "cpe" kind let a cpe23Type reference
// carry a 2.2 URI and vice versa, so an exporter would publish a reference
// whose declared type contradicts its own locator.
func TestCPEBindingMustMatchItsDeclaredType(t *testing.T) {
	const uri = "cpe:/a:vendor:product:1.0"
	const formatted = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"

	for _, tc := range []struct {
		refType string
		locator string
		want    bool
	}{
		{"cpe22Type", uri, true},
		{"cpe23Type", formatted, true},
		// Crossed: each locator is well formed, but not for the binding its
		// type declares.
		{"cpe22Type", formatted, false},
		{"cpe23Type", uri, false},
		// Values that are not CPEs at all but would slip past the shape
		// checks if the binding prefix were not required: the 2.2 branch
		// slices a fixed prefix length, and the 2.3 branch counts fields.
		{"cpe22Type", "cpe:a", false},
		{"cpe22Type", "cpe:2", false},
		{"cpe22Type", "xxxxx", false},
		{"cpe23Type", "foo:2.3:a:v:p:1:*:*:*:*:*:*:*", false},
	} {
		reference := ExternalReference{
			Category: ExternalReferenceCategorySecurity,
			Type:     tc.refType,
			Locator:  tc.locator,
		}
		if _, ok := reference.Normalized(); ok != tc.want {
			t.Errorf("%s with %q: ok = %v, want %v", tc.refType, tc.locator, ok, tc.want)
		}
	}
}

// TestCPE22RejectsOverlongBindings pins the component cap. The binding names
// seven components; an eighth is not a CPE. nvdtools accepts such a value and
// silently re-binds it without the extra component, which is why this is
// checked here rather than delegated — a dropped component is a changed
// assertion.
func TestCPE22RejectsOverlongBindings(t *testing.T) {
	for _, locator := range []string{
		"cpe:/a:v:p:1:u:e:l:extra",
		"cpe:/a:v:p:1:u:e:l:x:y",
	} {
		reference := ExternalReference{Category: ExternalReferenceCategorySecurity, Type: "cpe22Type", Locator: locator}
		if got, ok := reference.Normalized(); ok {
			t.Errorf("%q was accepted as a CPE 2.2 URI: %+v", locator, got)
		}
	}
	// Exactly seven components is the full binding and must be accepted.
	full := ExternalReference{Category: ExternalReferenceCategorySecurity, Type: "cpe22Type", Locator: "cpe:/a:v:p:1:u:e:l"}
	if _, ok := full.Normalized(); !ok {
		t.Fatal("a complete seven-component CPE 2.2 URI was rejected")
	}
}

// TestCycloneDXTypeCasingIsCanonical pins the case the SPDX-only registry
// missed. The type comparison is case-insensitive, so "WEBSITE" and "website"
// are one reference — without canonicalizing, which spelling reached the
// document depended on which witness folded first.
func TestCycloneDXTypeCasingIsCanonical(t *testing.T) {
	upper := ExternalReference{Type: "WEBSITE", Locator: "https://example.test"}
	lower := ExternalReference{Type: "website", Locator: "https://example.test"}

	normalized, ok := upper.Normalized()
	if !ok || normalized.Type != "website" {
		t.Fatalf("normalized = %+v, want the library's own spelling", normalized)
	}
	forward := MergeExternalReferences([]ExternalReference{upper}, []ExternalReference{lower})
	reverse := MergeExternalReferences([]ExternalReference{lower}, []ExternalReference{upper})
	if len(forward) != 1 || len(reverse) != 1 {
		t.Fatalf("merged to %d and %d records, want one each", len(forward), len(reverse))
	}
	if forward[0].Type != reverse[0].Type {
		t.Fatalf("published type depends on witness order: %q vs %q", forward[0].Type, reverse[0].Type)
	}
	// An SPDX-categorised reference still uses the SPDX registry.
	spdxRef, ok := ExternalReference{
		Category: ExternalReferenceCategorySecurity, Type: "ADVISORY", Locator: "https://advisories.test/x",
	}.Normalized()
	if !ok || spdxRef.Type != "advisory" {
		t.Fatalf("SPDX reference normalized to %+v, want the SPDX spelling", spdxRef)
	}
}

// TestCPE23RejectsEmptyComponents pins that every component carries a value.
// The binding has spellings for "any" and "not applicable" — "*" and "-" — so
// an empty component is malformed however well the separators count.
func TestCPE23RejectsEmptyComponents(t *testing.T) {
	for _, locator := range []string{
		"cpe:2.3:a::::::::::",
		"cpe:2.3:a:v::1.0:*:*:*:*:*:*:*",
		"cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:",
	} {
		reference := ExternalReference{Category: ExternalReferenceCategorySecurity, Type: "cpe23Type", Locator: locator}
		if got, ok := reference.Normalized(); ok {
			t.Errorf("%q was accepted with an empty component: %+v", locator, got)
		}
	}
	// The logical values and an escaped colon inside a component are fine.
	for _, locator := range []string{
		"cpe:2.3:a:v:p:1.0:*:-:*:*:*:*:*",
		`cpe:2.3:a:v:p\:1:1.0:*:*:*:*:*:*:*`,
		// A trailing component that is itself an escaped colon: splitting
		// without escape-awareness would produce an empty final field and
		// reject a well-formed value.
		`cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:\:`,
	} {
		reference := ExternalReference{Category: ExternalReferenceCategorySecurity, Type: "cpe23Type", Locator: locator}
		if _, ok := reference.Normalized(); !ok {
			t.Errorf("%q was rejected, but it is well formed", locator)
		}
	}
}

// TestCustomReferenceTypesMergeCaseSensitively pins the open vocabulary's
// merge rule. A recognized type is rewritten to its specification's spelling
// before keying, so those still collapse — but an unrecognized type keeps the
// spelling its source used, and folding case would merge two of them and then
// publish whichever witness arrived first.
func TestCustomReferenceTypesMergeCaseSensitively(t *testing.T) {
	upper := ExternalReference{Type: "Acme-ID", Locator: "https://acme.test/x"}
	lower := ExternalReference{Type: "acme-id", Locator: "https://acme.test/x"}

	forward := MergeExternalReferences([]ExternalReference{upper}, []ExternalReference{lower})
	reverse := MergeExternalReferences([]ExternalReference{lower}, []ExternalReference{upper})
	if len(forward) != 2 || len(reverse) != 2 {
		t.Fatalf("merged to %d and %d records; two spellings of an open-vocabulary type are two assertions", len(forward), len(reverse))
	}
	for i := range forward {
		if forward[i].Type != reverse[i].Type {
			t.Fatalf("published types depend on witness order: %+v vs %+v", forward, reverse)
		}
	}
	// A recognized type still collapses, because it was canonicalized first.
	known := MergeExternalReferences(
		[]ExternalReference{{Category: ExternalReferenceCategorySecurity, Type: "ADVISORY", Locator: "https://a.test/x"}},
		[]ExternalReference{{Category: ExternalReferenceCategorySecurity, Type: "advisory", Locator: "https://a.test/x"}},
	)
	if len(known) != 1 {
		t.Fatalf("recognized type merged to %d records, want one", len(known))
	}
}

// TestCycloneDXLocatorsAcceptBOMLinks pins that the CycloneDX url field is
// held to its schema's IRI-reference typing rather than to the web-URL gate.
// ADR-0037 links a merged document back to its sources with exactly this
// reference, so dropping BOM-Links would break the merged-export design
// before it is written.
func TestCycloneDXLocatorsAcceptBOMLinks(t *testing.T) {
	const link = "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1"
	reference := ExternalReference{Type: "bom", Locator: link}
	normalized, ok := reference.Normalized()
	if !ok {
		t.Fatal("a BOM-Link reference was rejected")
	}
	if normalized.Locator != link {
		t.Fatalf("locator = %q, want it carried unchanged", normalized.Locator)
	}
	// A web URL still passes the full gate, credentials and all.
	if _, ok := (ExternalReference{Type: "website", Locator: "https://example.test"}).Normalized(); !ok {
		t.Fatal("a web URL was rejected")
	}
	if _, ok := (ExternalReference{Type: "website", Locator: "https://user:pw@example.test/"}).Normalized(); ok {
		t.Fatal("credentials survived the IRI kind")
	}
	// A malformed BOM-Link is not a BOM-Link: the serial and version format
	// is cyclonedx-go's rule, not a second copy of it here.
	for _, bad := range []string{
		"urn:cdx:not-a-uuid/1",
		"urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79",
		"urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/0",
	} {
		if _, ok := (ExternalReference{Type: "bom", Locator: bad}).Normalized(); ok {
			t.Errorf("%q was accepted as a BOM-Link", bad)
		}
	}
	// An SPDX-typed url reference stays web-only: its specification says URL.
	spdxURL := ExternalReference{Category: ExternalReferenceCategorySecurity, Type: "url", Locator: link}
	if _, ok := spdxURL.Normalized(); ok {
		t.Fatal("a BOM-Link was accepted for an SPDX url-typed reference")
	}
	// mailto: is refused, matching the no-email decision Contact records.
	if _, ok := (ExternalReference{Type: "security-contact", Locator: "mailto:security@example.test"}).Normalized(); ok {
		t.Fatal("a mailto: locator was accepted, which stores an email address")
	}
}

// TestIRILocatorsPreserveTheWiderGrammar pins that the CycloneDX field keeps
// the locators its schema permits, with safety applied as a separate policy
// rather than by narrowing the grammar to the shapes Bomly happens to emit.
func TestIRILocatorsPreserveTheWiderGrammar(t *testing.T) {
	for _, locator := range []string{
		"urn:isbn:9780131103627",
		"ftp://ftp.example.test/pub/pkg.tar.gz",
		"git+ssh://git.example.test/owner/repo",
	} {
		reference := ExternalReference{Type: "distribution", Locator: locator}
		normalized, ok := reference.Normalized()
		if !ok {
			t.Errorf("%q was dropped, but its schema permits it", locator)
			continue
		}
		if normalized.Locator != locator {
			t.Errorf("%q was rewritten to %q", locator, normalized.Locator)
		}
	}
	// The policy still holds, whatever the grammar allows.
	for _, locator := range []string{
		"file:///etc/passwd",
		"jar:file:///tmp/x.jar!/a",
		"data:text/plain;base64,aGk=",
		"mailto:security@example.test",
		"ftp://user:pw@ftp.example.test/pkg.tgz",
		// A network-path reference names another authority without a scheme,
		// so it resolves somewhere other than the document's own host.
		"//evil.test/x",
	} {
		reference := ExternalReference{Type: "distribution", Locator: locator}
		if got, ok := reference.Normalized(); ok {
			t.Errorf("%q was accepted: %+v", locator, got)
		}
	}
}

// TestKnownSPDXTypeUnderTheWrongCategoryIsRefused pins the contradiction. An
// unrecognized type is carried — that is the open vocabulary, and forward
// compatibility. A type the specification does define, paired with the wrong
// category, is not a future type; letting it through published an invalid
// SPDX triple because its locator happened to be a bounded token.
func TestKnownSPDXTypeUnderTheWrongCategoryIsRefused(t *testing.T) {
	wrong := ExternalReference{
		Category: ExternalReferenceCategorySecurity,
		Type:     "purl", // the specification files purl under PACKAGE-MANAGER
		Locator:  "pkg:npm/a@1.0.0",
	}
	if got, ok := wrong.Normalized(); ok {
		t.Fatalf("a contradictory category/type pair was accepted: %+v", got)
	}
	// The same type under its own category is fine.
	right := ExternalReference{
		Category: ExternalReferenceCategoryPackageManager,
		Type:     "purl",
		Locator:  "pkg:npm/a@1.0.0",
	}
	if _, ok := right.Normalized(); !ok {
		t.Fatal("a correctly categorised purl reference was rejected")
	}
	// A genuinely unknown type still passes under any category.
	future := ExternalReference{
		Category: ExternalReferenceCategorySecurity,
		Type:     "invented-later",
		Locator:  "some-identifier",
	}
	if _, ok := future.Normalized(); !ok {
		t.Fatal("an unrecognized type was rejected; the vocabulary is open")
	}
}

// TestUnicodeIRILocatorsSurvive pins that an IRI keeps the characters its
// grammar allows. net/url renders a URI, so it percent-encodes Unicode:
// requiring the parse to round-trip byte-for-byte silently dropped valid
// locators.
func TestUnicodeIRILocatorsSurvive(t *testing.T) {
	for _, locator := range []string{
		"ftp://\u4f8b\u3048.\u30c6\u30b9\u30c8/\u8cc7\u6599",
		"urn:isbn:9780131103627",
		// A web URL takes the URLFormReference path instead, which
		// re-serializes; Unicode hosts there are a separate question, tracked
		// against NormalizeURL rather than asserted here.
	} {
		reference := ExternalReference{Type: "distribution", Locator: locator}
		normalized, ok := reference.Normalized()
		if !ok {
			t.Errorf("%q was dropped, but its grammar permits it", locator)
			continue
		}
		if normalized.Locator != locator {
			t.Errorf("%q was rewritten to %q", locator, normalized.Locator)
		}
	}
	// The policy still bites on a Unicode host.
	if _, ok := (ExternalReference{Type: "distribution", Locator: "ftp://u:p@\u4f8b\u3048.\u30c6\u30b9\u30c8/x"}).Normalized(); ok {
		t.Fatal("credentials survived on a Unicode authority")
	}
}

// TestCPEEscapedBackslashesCountAsSeparators pins backslash parity. A run of
// backslashes escapes itself pairwise, so an even run leaves the next
// character unquoted -- in "vendor\\\\:product" the two backslashes encode one
// literal backslash and the colon after them is a real field separator.
func TestCPEEscapedBackslashesCountAsSeparators(t *testing.T) {
	// Twelve separators: the escaped backslash does not quote the colon.
	valid := `cpe:2.3:a:vendor\\:product:1:*:*:*:*:*:*:*`
	if got := countUnescapedColons(valid); got != cpe23FieldCount-1 {
		t.Fatalf("counted %d separators in %s, want %d", got, valid, cpe23FieldCount-1)
	}
	reference := ExternalReference{Category: ExternalReferenceCategorySecurity, Type: "cpe23Type", Locator: valid}
	if _, ok := reference.Normalized(); !ok {
		t.Fatalf("%s was rejected, but it is a well-formed CPE", valid)
	}
	// An odd run still quotes the colon, so this one is a component short.
	short := `cpe:2.3:a:vendor\\\\\\:product:1:*:*:*:*:*:*:*`
	_ = short
	odd := `cpe:2.3:a:vendor\:product:1:*:*:*:*:*:*:*`
	if got := countUnescapedColons(odd); got != cpe23FieldCount-2 {
		t.Fatalf("counted %d separators in %s, want %d", got, odd, cpe23FieldCount-2)
	}
	if _, ok := (ExternalReference{Category: ExternalReferenceCategorySecurity, Type: "cpe23Type", Locator: odd}).Normalized(); ok {
		t.Fatalf("%s was accepted, but its escaped colon leaves it a component short", odd)
	}
}

// TestRelativeIRIReferencesArePreserved pins that a relative locator survives.
// It resolves against the document it was written in, which for the
// single-source flows ADR-0037 scopes its fixed-point promise to is exactly
// the right base — so carrying it is faithful and dropping it loses an
// assertion the source made.
func TestRelativeIRIReferencesArePreserved(t *testing.T) {
	for _, locator := range []string{
		"../advisories/CVE-1234",
		"advisories/CVE-1234",
		"/advisories/CVE-1234",
		"#security",
	} {
		reference := ExternalReference{Type: "advisories", Locator: locator}
		normalized, ok := reference.Normalized()
		if !ok {
			t.Errorf("%q was dropped, but its schema permits a relative reference", locator)
			continue
		}
		if normalized.Locator != locator {
			t.Errorf("%q was rewritten to %q", locator, normalized.Locator)
		}
	}
	// A network-path reference is the one relative form that changes the
	// authority, so it stays refused.
	for _, locator := range []string{"//evil.test/x", "//user:pw@evil.test/x", "//@", "//"} {
		if got, ok := (ExternalReference{Type: "advisories", Locator: locator}).Normalized(); ok {
			t.Errorf("%q was accepted: %+v", locator, got)
		}
	}
	// An SPDX url-typed reference is still web-only; only the CycloneDX field
	// is typed as an IRI reference.
	spdxRel := ExternalReference{Category: ExternalReferenceCategorySecurity, Type: "advisory", Locator: "../x"}
	if _, ok := spdxRel.Normalized(); ok {
		t.Fatal("a relative locator was accepted for an SPDX advisory reference")
	}
}

// TestIRILocatorsRejectMalformedEscapes pins the one piece of the grammar
// net/url does not enforce on opaque and relative references. Publishing
// "urn:x:foo%ZZ" puts a value in the document that every consumer's own
// parser rejects.
func TestIRILocatorsRejectMalformedEscapes(t *testing.T) {
	for _, locator := range []string{
		"urn:x:foo%ZZ",
		"urn:x:foo%",
		"urn:x:foo%A",
		"../advisories/%GG",
		"ftp://a.test/%zz",
	} {
		if got, ok := (ExternalReference{Type: "distribution", Locator: locator}).Normalized(); ok {
			t.Errorf("%q was accepted with a malformed escape: %+v", locator, got)
		}
	}
	// Well-formed escapes still pass, in both cases.
	for _, locator := range []string{"urn:x:foo%2Fbar", "urn:x:foo%2fbar", "../advisories/%20x"} {
		if _, ok := (ExternalReference{Type: "distribution", Locator: locator}).Normalized(); !ok {
			t.Errorf("%q was rejected, but its escapes are well formed", locator)
		}
	}
}

// TestWebSchemesDoNotFallBackToTheIRIPath pins that a locator naming http or
// https is judged by the web gate and gets no second hearing as a generic
// IRI. The generic path asks only for a scheme, no credentials, and nothing
// sensitive — so a hostless URL that the web gate rejected was falling
// through and being published unchanged.
func TestWebSchemesDoNotFallBackToTheIRIPath(t *testing.T) {
	for _, locator := range []string{
		"https:///advisory", // no host
		"http://:8080/x",    // no hostname
		"https://",          // nothing at all
		"HTTPS:///advisory", // the scheme is compared case-insensitively
	} {
		if got, ok := (ExternalReference{Type: "website", Locator: locator}).Normalized(); ok {
			t.Errorf("%q bypassed the web gate and was published as %q", locator, got.Locator)
		}
	}
	// A web URL that passes the gate is unaffected, and non-web schemes still
	// take the generic path.
	if _, ok := (ExternalReference{Type: "website", Locator: "https://x.test/ok"}).Normalized(); !ok {
		t.Fatal("a valid web URL was rejected")
	}
	if _, ok := (ExternalReference{Type: "distribution", Locator: "ftp://a.test/pkg.tgz"}).Normalized(); !ok {
		t.Fatal("a non-web IRI was rejected")
	}
}

// TestIRILocatorsRejectExcludedCharacters pins RFC 3986's excluded set. These
// are legal only percent-encoded, so publishing them unescaped emits a
// locator that violates the schema's iri-reference type.
func TestIRILocatorsRejectExcludedCharacters(t *testing.T) {
	for _, locator := range []string{
		"urn:example:{value}",
		"urn:example:a|b",
		`urn:example:a\b`,
		"urn:example:a^b",
		"urn:example:a`b",
		`urn:example:a"b`,
		"urn:example:a<b>",
		"../advisories/{id}",
	} {
		if got, ok := (ExternalReference{Type: "distribution", Locator: locator}).Normalized(); ok {
			t.Errorf("%q was accepted with an excluded character: %+v", locator, got)
		}
	}
	// Percent-encoded, they are legal.
	if _, ok := (ExternalReference{Type: "distribution", Locator: "urn:example:%7Bvalue%7D"}).Normalized(); !ok {
		t.Fatal("a percent-encoded brace was rejected")
	}
	// Non-ASCII stays legal: an IRI is exactly the thing that may carry it.
	if _, ok := (ExternalReference{Type: "distribution", Locator: "ftp://例え.テスト/資料"}).Normalized(); !ok {
		t.Fatal("a Unicode IRI was rejected by the character rule")
	}
	// And the sub-delimiters an IRI may carry unescaped are unaffected.
	for _, locator := range []string{"urn:example:a+b", "urn:example:a,b", "urn:example:a$b", "urn:example:a!b"} {
		if _, ok := (ExternalReference{Type: "distribution", Locator: locator}).Normalized(); !ok {
			t.Errorf("%q was rejected, but its characters are legal unescaped", locator)
		}
	}
}

// TestIRICharacterRuleIsAnAllowlist pins the closed form of the rule. A
// denylist is never finished -- the ASCII exclusions could not have caught a
// Unicode noncharacter -- so a character is publishable because the
// specification names it, not because nobody has reported it yet.
func TestIRICharacterRuleIsAnAllowlist(t *testing.T) {
	t.Run("excluded Unicode is refused", func(t *testing.T) {
		for _, locator := range []string{
			"urn:example:\ufdd0",     // noncharacter, between the ucschar ranges
			"urn:example:\ufdef",     // the other end of that block
			"urn:example:\ufffe",     // plane-ending noncharacter
			"urn:example:\U0001fffe", // and on a supplementary plane
			// A C1 control mid-string: at the end it would simply be
			// trimmed as Unicode whitespace, which is a different rule.
			"urn:example:a\u0085b",
			"urn:example:a\u0080b",
			// Private-use code points: the grammar admits these only inside
			// a query, and they have no interoperable meaning anywhere.
			"urn:example:\ue000",
			"ftp://host.test/\ue000",
			"ftp://host.test/x?q=\ue000",
			"urn:example:\U000F0000",
		} {
			if got, ok := (ExternalReference{Type: "distribution", Locator: locator}).Normalized(); ok {
				t.Errorf("%q was accepted: %+v", locator, got)
			}
		}
	})

	t.Run("permitted Unicode survives", func(t *testing.T) {
		for _, locator := range []string{
			"ftp://\u4f8b\u3048.\u30c6\u30b9\u30c8/\u8cc7\u6599", // CJK and kana, inside A0-D7FF
			"urn:example:\ufdf0",     // just past the noncharacter block
			"urn:example:\U0001f600", // a supplementary-plane character
		} {
			if _, ok := (ExternalReference{Type: "distribution", Locator: locator}).Normalized(); !ok {
				t.Errorf("%q was rejected, but the grammar admits it", locator)
			}
		}
	})

	t.Run("the ASCII set is the specification's", func(t *testing.T) {
		// Every reserved and unreserved character, unescaped.
		legal := "urn:example:aZ09-._~:/?#[]@!$&'()*+,;="
		if _, ok := (ExternalReference{Type: "distribution", Locator: legal}).Normalized(); !ok {
			t.Errorf("%q was rejected, but every character in it is legal", legal)
		}
		for _, locator := range []string{
			"urn:example:{v}", `urn:example:a\b`, "urn:example:a|b",
			"urn:example:a^b", "urn:example:a`b", `urn:example:a"b`,
			"urn:example:a<b>",
		} {
			if _, ok := (ExternalReference{Type: "distribution", Locator: locator}).Normalized(); ok {
				t.Errorf("%q was accepted with an excluded character", locator)
			}
		}
	})
}
