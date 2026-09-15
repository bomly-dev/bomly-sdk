package sbom

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/internal/testnodes"
)

// Every ingest entry point refuses an input over MaxDocumentBytes before
// parsing it. The CLI bounds a file at this size before reading it; a
// consumer of this package handing over bytes it obtained some other way gets
// the same bound here rather than none.
func TestOversizedDocumentsAreRefusedBeforeParsing(t *testing.T) {
	oversized := make([]byte, MaxDocumentBytes+1)
	oversized[0] = '{'
	if _, err := UnmarshalJSON(oversized, TargetCycloneDX16JSON); !errors.Is(err, ErrDocumentTooLarge) {
		t.Errorf("UnmarshalJSON error = %v, want %v", err, ErrDocumentTooLarge)
	}
	if _, _, err := UnmarshalAutoJSON(oversized); !errors.Is(err, ErrDocumentTooLarge) {
		t.Errorf("UnmarshalAutoJSON error = %v, want %v", err, ErrDocumentTooLarge)
	}
	if _, err := DetectJSONTarget(oversized); !errors.Is(err, ErrDocumentTooLarge) {
		t.Errorf("DetectJSONTarget error = %v, want %v", err, ErrDocumentTooLarge)
	}
}

// CycloneDX makes bom-ref optional. Two components without one used to share
// the key "" and the second overwrote the first, so a third-party document
// lost inventory on ingest. Each now keeps its own entry, keyed on what it
// does carry.
func TestComponentsWithoutBOMRefAllSurviveIngest(t *testing.T) {
	raw := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[
	  {"type":"library","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"},
	  {"type":"library","name":"right-pad","version":"2.0.0","purl":"pkg:npm/right-pad@2.0.0"},
	  {"type":"library","name":"no-purl","version":"0.1.0"},
	  {"type":"library","name":"no-purl","version":"0.1.0"}
	]}`
	doc, _, err := UnmarshalAutoJSON([]byte(raw))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(doc.Components) != 4 {
		t.Fatalf("components = %d, want all four kept: %+v", len(doc.Components), doc.Components)
	}
	seen := map[string]bool{}
	for _, component := range doc.Components {
		if component.ID == "" {
			t.Errorf("component %q has no reference", component.Name)
		}
		if seen[component.ID] {
			t.Errorf("reference %q is shared by two components", component.ID)
		}
		seen[component.ID] = true
	}
	if !seen["pkg:npm/left-pad@1.3.0"] || !seen["no-purl@0.1.0"] {
		t.Errorf("references = %v, want the package URL and name@version used where available", seen)
	}
}

// A stated bom-ref is still the reference, whatever else the component
// carries.
func TestAStatedBOMRefIsTheReference(t *testing.T) {
	raw := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[
	  {"bom-ref":"ref-1","type":"library","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"}
	]}`
	doc, _, err := UnmarshalAutoJSON([]byte(raw))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(doc.Components) != 1 || doc.Components[0].ID != "ref-1" {
		t.Fatalf("components = %+v, want the stated bom-ref kept", doc.Components)
	}
}

// A key derived for a ref-less component never takes a stated bom-ref, in
// either document order: the stated ref may be the derived key's suffixed
// spelling, or the derived key's base itself. Each component keeps its own
// entry and every stated ref still names its own component.
func TestADerivedReferenceNeverTakesAStatedBOMRef(t *testing.T) {
	cases := map[string]string{
		"stated suffix first": `[
		  {"bom-ref":"pkg:npm/foo@1.0.0-2","type":"library","name":"stated","version":"9.9.9"},
		  {"type":"library","name":"foo","version":"1.0.0","purl":"pkg:npm/foo@1.0.0"},
		  {"type":"library","name":"foo","version":"1.0.0","purl":"pkg:npm/foo@1.0.0"}
		]`,
		"stated suffix after": `[
		  {"type":"library","name":"foo","version":"1.0.0","purl":"pkg:npm/foo@1.0.0"},
		  {"type":"library","name":"foo","version":"1.0.0","purl":"pkg:npm/foo@1.0.0"},
		  {"bom-ref":"pkg:npm/foo@1.0.0-1","type":"library","name":"stated","version":"9.9.9"}
		]`,
		"stated base after": `[
		  {"type":"library","name":"foo","version":"1.0.0","purl":"pkg:npm/foo@1.0.0"},
		  {"bom-ref":"pkg:npm/foo@1.0.0","type":"library","name":"stated","version":"9.9.9"}
		]`,
	}
	for name, components := range cases {
		t.Run(name, func(t *testing.T) {
			raw := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":` + components + `}`
			var stated []map[string]any
			if err := json.Unmarshal([]byte(components), &stated); err != nil {
				t.Fatalf("fixture: %v", err)
			}
			doc, _, err := UnmarshalAutoJSON([]byte(raw))
			if err != nil {
				t.Fatalf("ingest: %v", err)
			}
			if len(doc.Components) != len(stated) {
				t.Fatalf("components = %d, want all %d kept: %+v", len(doc.Components), len(stated), doc.Components)
			}
			byID := map[string]Component{}
			for _, component := range doc.Components {
				if _, dup := byID[component.ID]; dup {
					t.Fatalf("reference %q is shared by two components: %+v", component.ID, doc.Components)
				}
				byID[component.ID] = component
			}
			for _, entry := range stated {
				ref, ok := entry["bom-ref"].(string)
				if !ok {
					continue
				}
				if got := byID[ref].Name; got != "stated" {
					t.Errorf("stated bom-ref %q names %q, want the component that stated it", ref, got)
				}
			}
		})
	}
}

// A CycloneDX document's revision is decoded with its serial: a direct
// UnmarshalJSON -> MarshalJSON round trip used to write revision 1 of a
// document it had read at revision 4, which changes the BOM-Link identity.
func TestCycloneDXRevisionSurvivesADirectRoundTrip(t *testing.T) {
	raw := `{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79","version":4,"components":[]}`
	doc, err := UnmarshalJSON([]byte(raw), TargetCycloneDX16JSON)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if doc.SerialVersion != 4 {
		t.Fatalf("SerialVersion = %d, want the document's revision 4", doc.SerialVersion)
	}
	out, err := MarshalJSON(doc, TargetCycloneDX16JSON, EncodeOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(out, &bom); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if bom.Version != 4 {
		t.Fatalf("re-exported version = %d, want 4", bom.Version)
	}
}

// SPDX identifiers are ASCII letters, digits, "." and "-". A Unicode letter
// used to be kept and emitted into an SPDXRef conforming consumers reject.
func TestSPDXIdentifiersAreASCII(t *testing.T) {
	cases := map[string]string{
		"pkg:npm/left-pad@1.3.0": "pkg-npm-left-pad-1.3.0",
		"módulo/über":            "m-dulo-ber",
		"日本語":                    "pkg",
		"":                       "pkg",
		"a b":                    "a-b",
	}
	for raw, want := range cases {
		if got := sanitizeSPDXID(raw); got != want {
			t.Errorf("sanitizeSPDXID(%q) = %q, want %q", raw, got, want)
		}
		for _, r := range sanitizeSPDXID(raw) {
			if r > 0x7f {
				t.Errorf("sanitizeSPDXID(%q) emitted the non-ASCII rune %q", raw, r)
			}
		}
	}
}

// Two values that sanitize to one idstring get a suffix, and a third value
// that sanitizes straight to that suffixed spelling gets a different one: the
// allocator records every identifier it hands out, not only the bases.
func TestSPDXIDAllocatorNeverRepeatsAnIdentifier(t *testing.T) {
	ids := newSPDXIDAllocator(4)
	got := []string{ids.allocate("a"), ids.allocate("a"), ids.allocate("a-1"), ids.allocate("a-1"), ids.allocate("a")}
	seen := map[string]bool{}
	for _, id := range got {
		if seen[id] {
			t.Fatalf("identifier %q issued twice in %v", id, got)
		}
		seen[id] = true
	}
	if got[0] != "a" || got[1] != "a-1" {
		t.Errorf("first two = %q, %q; want the base then its first suffix", got[0], got[1])
	}
}

// The same rule at both sites that mint SPDX identifiers: packages, and the
// external document references a merged export writes for its sources.
func TestCollidingIdentifiersStayDistinctAcrossThreeSources(t *testing.T) {
	checksum := sdk.Digest{Algorithm: sdk.DigestAlgorithmSHA256, Value: strings.Repeat("0", 64)}
	doc := &Document{
		Namespace: "https://bomly.dev/spdx/merged",
		Sources: []sdk.DocumentAssertions{
			{Identity: "https://acme.example/a_b", Checksum: &checksum},
			{Identity: "https://acme.example/a+b", Checksum: &checksum},
			{Identity: "https://acme.example/a-b-1", Checksum: &checksum},
		},
	}
	refs := spdxSourceLinks(doc)
	if len(refs) != 3 {
		t.Fatalf("refs = %+v, want one per source", refs)
	}
	seen := map[string]bool{}
	for _, ref := range refs {
		if seen[string(ref.DocumentRefID)] {
			t.Errorf("two sources share the reference id %q", ref.DocumentRefID)
		}
		seen[string(ref.DocumentRefID)] = true
	}

	g := sdk.New()
	for _, name := range []string{"a_b", "a+b", "a-b-1"} {
		if err := g.AddNode(testnodes.Dep(sdk.Coordinates{Ecosystem: sdk.EcosystemNPM, Name: name, Version: "1.0.0"})); err != nil {
			t.Fatalf("add node: %v", err)
		}
	}
	out, err := MarshalDepGraphJSON(g, TargetSPDX23JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	var spdx struct {
		Packages []struct {
			SPDXID string `json:"SPDXID"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(out, &spdx); err != nil {
		t.Fatalf("decode: %v", err)
	}
	seen = map[string]bool{}
	for _, pkg := range spdx.Packages {
		if seen[pkg.SPDXID] {
			t.Errorf("two packages share the SPDXID %q", pkg.SPDXID)
		}
		seen[pkg.SPDXID] = true
	}
}

// A RootComponentID that names nothing the graph exports is not an override,
// and must not suppress the synthesized project root a multi-root graph needs.
func TestAnUnmatchedRootOverrideDoesNotSuppressTheSynthesizedRoot(t *testing.T) {
	doc, err := FromDepGraph(mustMultiRootGraph(t), BuildOptions{
		ProjectRoot:     &ProjectRoot{Name: "demo"},
		RootComponentID: "pkg:npm/does-not-exist@0.0.0",
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(doc.Roots) != 1 || !IsProjectRootComponent(Component{ID: doc.Roots[0]}) {
		t.Fatalf("roots = %v, want the one synthesized project root", doc.Roots)
	}
}
