package model

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestAssertionsMergeFromGatesBothSidesBeforeFillingGaps(t *testing.T) {
	dst := Assertions{
		Homepage:    "https://user:pw@example.test/", // unpublishable: would otherwise block the incoming value
		Description: "kept",
		CPEs:        []string{"cpe:2.3:a:v:p:1:*:*:*:*:*:*:*"},
		Licenses:    []PackageLicense{{Value: "MIT", SPDXExpression: "MIT", Type: LicenseTypeDeclared}},
	}
	src := Assertions{
		Homepage:    "https://example.test/",
		Description: "ignored: dst has one",
		Supplier:    &Contact{Kind: ContactKindOrganization, Name: "Acme"},
		CPEs:        []string{"cpe:2.3:a:w:p:1:*:*:*:*:*:*:*", "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*"},
		Licenses:    []PackageLicense{{Value: "Apache-2.0", SPDXExpression: "Apache-2.0", Type: LicenseTypeConcluded}},
		Copyright:   "(c) Acme",
	}
	dst.MergeFrom(src)
	if dst.Homepage != "https://example.test/" || dst.Description != "kept" || dst.Supplier == nil || dst.Supplier.Name != "Acme" || dst.Copyright != "(c) Acme" {
		t.Fatalf("scalars: %+v", dst)
	}
	if len(dst.CPEs) != 2 || len(dst.Licenses) != 2 {
		t.Fatalf("sets did not union: %+v", dst)
	}
	var nilAssertions *Assertions
	nilAssertions.MergeFrom(src)
}

func TestAssertionsNormalizedIsIdempotentAndCloneIsDeep(t *testing.T) {
	in := Assertions{
		Description:        "  a \x07 description ",
		Homepage:           "not a url",
		Supplier:           &Contact{Kind: ContactKindOrganization, Name: "Acme\n"},
		ExternalReferences: []ExternalReference{{Category: "OTHER", Type: "website", Locator: "https://b.test"}, {Category: "OTHER", Type: "website", Locator: "https://a.test"}},
		CPEs:               []string{"b", "a", "a"},
		Digests:            []Digest{{Algorithm: DigestAlgorithmSHA256, Value: "ABC"}, {Algorithm: "crc32", Value: "zz"}},
	}
	once := in.Normalized()
	twice := once.Normalized()
	if !reflect.DeepEqual(once, twice) {
		t.Fatalf("not idempotent:\n%+v\n%+v", once, twice)
	}
	if once.Homepage != "" || once.Description != NormalizeDescription(in.Description) || len(once.CPEs) != 2 || once.CPEs[0] != "b" {
		t.Fatalf("gates: %+v", once)
	}
	clone := once.Clone()
	clone.CPEs[0] = "z"
	if once.CPEs[0] != "b" {
		t.Fatal("Clone shares slices with its source")
	}
}

// TestPackageJSONStaysFlatAcrossTheEmbedding pins that embedding Assertions
// did not move a single key: the wire shape is the pre-embedding one.
func TestPackageJSONStaysFlatAcrossTheEmbedding(t *testing.T) {
	pkg := Package{
		Coordinates: Coordinates{PURL: "pkg:npm/a@1.0.0", Name: "a", Version: "1.0.0"},
		Assertions: Assertions{
			Description: "d", Homepage: "https://a.test/", Supplier: &Contact{Kind: ContactKindOrganization, Name: "S"},
			Originator: &Contact{Kind: ContactKindPerson, Name: "O"}, CPEs: []string{"cpe:2.3:a:v:p:1:*:*:*:*:*:*:*"},
			Digests:  []Digest{{Algorithm: DigestAlgorithmSHA256, Value: strings.Repeat("ab", 32)}},
			Licenses: []PackageLicense{{Value: "MIT", SPDXExpression: "MIT"}}, Copyright: "(c)",
			ExternalReferences: []ExternalReference{{Category: "OTHER", Type: "website", Locator: "https://a.test/"}},
		},
		Matched: true,
	}
	data, err := json.Marshal(pkg)
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"purl", "name", "version", "description", "homepage", "supplier", "originator", "cpes", "digests", "licenses", "copyright", "external_references", "matched"} {
		if _, ok := keys[key]; !ok {
			t.Errorf("key %q is not at the top level: %s", key, data)
		}
	}
	if _, nested := keys["assertions"]; nested {
		t.Fatalf("assertions were nested: %s", data)
	}
	var back Package
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.Description != "d" || back.Supplier == nil || len(back.CPEs) != 1 {
		t.Fatalf("round trip lost promoted fields: %+v", back)
	}
}

// TestDependencyNodeWireIsUnchanged decodes a pre-embedding node payload and
// re-encodes it byte for byte.
func TestDependencyNodeWireIsUnchanged(t *testing.T) {
	payload := `{"nodes":[{"kind":"dependency","id":"pkg:npm/a@1.0.0","purl":"pkg:npm/a@1.0.0","ecosystem":"npm","name":"a","version":"1.0.0","cpes":["cpe:2.3:a:v:p:1:*:*:*:*:*:*:*"],"copyright":"(c)","licenses":[{"value":"MIT","spdx_expression":"MIT"}],"description":"d","homepage":"https://a.test/","supplier":{"kind":"organization","name":"S"},"package_ref":"pkg:npm/a@1.0.0"}]}`
	var g Graph
	if err := json.Unmarshal([]byte(payload), &g); err != nil {
		t.Fatal(err)
	}
	dep, ok := g.DependencyNode("pkg:npm/a@1.0.0")
	if !ok || dep.Description != "d" || dep.Supplier == nil || dep.Copyright != "(c)" || len(dep.Licenses) != 1 {
		t.Fatalf("promoted fields not decoded: %+v", dep)
	}
	first, _ := json.Marshal(&g)
	var again Graph
	if err := json.Unmarshal(first, &again); err != nil {
		t.Fatal(err)
	}
	second, _ := json.Marshal(&again)
	if string(first) != string(second) {
		t.Fatalf("not a fixed point:\n%s\n%s", first, second)
	}
	for _, key := range []string{`"description":"d"`, `"homepage":"https://a.test/"`, `"copyright":"(c)"`, `"cpes":[`, `"licenses":[`} {
		if !strings.Contains(string(first), key) {
			t.Errorf("encoded node lost %s: %s", key, first)
		}
	}
}
