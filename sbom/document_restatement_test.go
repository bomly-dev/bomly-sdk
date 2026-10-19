package sbom

import (
	"encoding/json"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bomly-dev/bomly-sdk/internal/testnodes"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"

	"github.com/bomly-dev/bomly-sdk/model"
)

// A single source whose graph was transformed after ingest -- scope-filtered,
// enriched, degraded -- is a different document with one input, and it says
// so: its own identity, timestamp, name and comment, with the source linked
// rather than adopted (ADR-0042 as amended by issue #433). Before the
// amendment a `--scope runtime` export of one SBOM republished that SBOM's
// namespace over a subset of its inventory, two documents sharing one name.
//
// The caller's declaration is the only signal; this package cannot tell a
// filtered graph from a whole one. So the default -- no declaration -- is the
// safe side, and these tests pass no RestatesSource at all.
func TestATransformedConversionMintsItsOwnIdentity(t *testing.T) {
	_, entry := ingestDocument(t, documentRichSPDX)
	doc, err := FromGraphEntries(entry.Graph, []model.GraphEntry{entry}, BuildOptions{Created: fixedExportTime()})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	const sourceNamespace = "https://acme.example/spdx/acme-platform-7f3c"
	if doc.Namespace == sourceNamespace {
		t.Fatalf("a transformed export republished its source's namespace %q", doc.Namespace)
	}
	if !strings.HasPrefix(doc.Namespace, "https://bomly.dev/spdx/") {
		t.Fatalf("namespace = %q, want one minted by this export", doc.Namespace)
	}
	if doc.Name != defaultDocumentName {
		t.Fatalf("name = %q, want the default rather than the source's", doc.Name)
	}
	if doc.Assertions.Comment != "" {
		t.Fatalf("comment = %q, want none: it described the source's full contents", doc.Assertions.Comment)
	}
	if !doc.Created.Equal(fixedExportTime()) {
		t.Fatalf("created = %v, want this export's own time %v, not the source's", doc.Created, fixedExportTime())
	}
	if len(doc.Sources) != 1 {
		t.Fatalf("sources = %d, want the one document read", len(doc.Sources))
	}
	// Creators still union: the source did produce this document's inventory.
	var credited bool
	for _, creator := range doc.Assertions.Creators {
		if creator.Name == "Acme Corp" {
			credited = true
		}
	}
	if !credited {
		t.Fatalf("creators = %+v, want the source's organization credited", doc.Assertions.Creators)
	}
}

// The identity a transformed export does not adopt is not lost: it is written
// as a link, in whichever form the target format has for one.
func TestATransformedConversionLinksItsSource(t *testing.T) {
	t.Run("spdx", func(t *testing.T) {
		_, entry := ingestDocument(t, documentRichSPDX)
		raw, err := MarshalGraphEntriesJSON(entry.Graph, []model.GraphEntry{entry}, TargetSPDX23JSON,
			BuildOptions{Created: fixedExportTime()}, EncodeOptions{Pretty: true})
		if err != nil {
			t.Fatalf("export: %v", err)
		}
		refs := spdxExternalDocumentRefs(t, raw)
		if len(refs) != 1 {
			t.Fatalf("externalDocumentRefs = %+v, want exactly the source", refs)
		}
		if refs[0].URI != "https://acme.example/spdx/acme-platform-7f3c" {
			t.Fatalf("linked %q, want the source namespace", refs[0].URI)
		}
		if refs[0].Checksum.Value != ingestChecksumHex(documentRichSPDX) {
			t.Fatalf("checksum = %q, want a digest of the source bytes", refs[0].Checksum.Value)
		}
	})
	t.Run("cyclonedx", func(t *testing.T) {
		_, entry := ingestDocument(t, serialCycloneDX)
		raw, err := MarshalGraphEntriesJSON(entry.Graph, []model.GraphEntry{entry}, TargetCycloneDX16JSON,
			BuildOptions{Created: fixedExportTime()}, EncodeOptions{Pretty: true})
		if err != nil {
			t.Fatalf("export: %v", err)
		}
		var bom cdx.BOM
		if err := json.Unmarshal(raw, &bom); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if bom.SerialNumber == "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79" {
			t.Fatalf("a transformed export republished its source's serial %q", bom.SerialNumber)
		}
		refs := cycloneDXSourceRefs(t, raw)
		if len(refs) != 1 {
			t.Fatalf("bom references = %+v, want exactly the source", refs)
		}
		if refs[0].URL != "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1" {
			t.Fatalf("linked %q, want the source's BOM-Link", refs[0].URL)
		}
		if refs[0].Hashes == nil || len(*refs[0].Hashes) == 0 {
			t.Fatalf("the source link carries no hash")
		}
	})
}

// The declaration means nothing for a merge: two sources are two documents
// whatever the caller says, and both are linked.
func TestRestatementFlagIsIgnoredByAMerge(t *testing.T) {
	_, first := ingestDocument(t, documentRichSPDX)
	_, second := ingestDocument(t, serialCycloneDX)
	merged := model.New()
	if err := model.MergeGraph(merged, first.Graph); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if err := model.MergeGraph(merged, second.Graph); err != nil {
		t.Fatalf("merge: %v", err)
	}
	doc, err := FromGraphEntries(merged, []model.GraphEntry{first, second}, BuildOptions{RestatesSource: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if doc.Namespace == "https://acme.example/spdx/acme-platform-7f3c" {
		t.Fatalf("a merge adopted one source's namespace despite the flag")
	}
	if got := documentSourceLinks(doc, documentIdentity{Namespace: doc.Namespace}); len(got) != 2 {
		t.Fatalf("source links = %+v, want both documents", got)
	}
}

// A document beside a natively resolved manifest is a merge with one source,
// whatever the caller declared: the graph holds packages the document never
// named, so publishing it under the document's identity would be the same
// collision as a filtered export. The model decides this from the entries,
// so no caller has to remember to.
func TestADocumentBesideANativeManifestIsNotRestated(t *testing.T) {
	_, ingested := ingestDocument(t, documentRichSPDX)
	native := model.New()
	if err := native.AddNode(testnodes.Dep(model.Coordinates{Ecosystem: model.EcosystemNPM, Name: "left-pad", Version: "1.3.0"})); err != nil {
		t.Fatalf("add native node: %v", err)
	}
	merged := model.New()
	for _, g := range []*model.Graph{ingested.Graph, native} {
		if err := model.MergeGraph(merged, g); err != nil {
			t.Fatalf("merge: %v", err)
		}
	}
	entries := []model.GraphEntry{ingested, {Graph: native}}
	doc, err := FromGraphEntries(merged, entries, BuildOptions{RestatesSource: true, Created: fixedExportTime()})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if doc.Namespace == "https://acme.example/spdx/acme-platform-7f3c" {
		t.Fatalf("a mixed export republished its one document's namespace over packages that document never named")
	}
	if got := documentSourceLinks(doc, documentIdentity{Namespace: doc.Namespace}); len(got) != 1 {
		t.Fatalf("source links = %+v, want the document linked", got)
	}

	// The same entries without the native graph beside them still restate.
	alone, err := FromGraphEntries(ingested.Graph, []model.GraphEntry{ingested}, BuildOptions{RestatesSource: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if alone.Namespace != "https://acme.example/spdx/acme-platform-7f3c" {
		t.Fatalf("a lone document stopped restating: namespace = %q", alone.Namespace)
	}
}

// A restating conversion of a Bomly SPDX document adopts the revision the
// document stated in Bomly's creator-comment carrier along with its identity:
// the SPDX export repeats it, and the CycloneDX export, whose serial is the
// namespace's UUID, numbers itself the same revision rather than 1. Only the
// carrier counts; the lifecycle stays the exporting caller's claim.
func TestARestatingConversionAdoptsTheSourcesStatedRevision(t *testing.T) {
	const bomlySPDX = `{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "demo",
  "documentNamespace": "https://bomly.dev/spdx/0f3c9a2e-5d4b-4c6a-8e1f-7a2b3c4d5e6f",
  "creationInfo": {
    "created": "2026-01-02T03:04:05Z",
    "creators": ["Tool: bomly-cli-0.28.2"],
    "comment": "SecurityContact: security@example.com\nbomly:lifecycle=post-build;document_version=3"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-widget",
      "name": "widget",
      "versionInfo": "1.0.0",
      "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/widget@1.0.0"}
      ]
    }
  ]
}`
	_, entry := ingestDocument(t, bomlySPDX)
	if entry.Document.Version != 3 {
		t.Fatalf("ingested version = %d, want the carrier's 3", entry.Document.Version)
	}
	doc, err := FromGraphEntries(entry.Graph, []model.GraphEntry{entry}, BuildOptions{RestatesSource: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if doc.Namespace != "https://bomly.dev/spdx/0f3c9a2e-5d4b-4c6a-8e1f-7a2b3c4d5e6f" {
		t.Fatalf("namespace = %q, want the source's adopted", doc.Namespace)
	}
	if doc.SerialNumber != "urn:uuid:0f3c9a2e-5d4b-4c6a-8e1f-7a2b3c4d5e6f" || doc.SerialVersion != 3 {
		t.Fatalf("serial = %q revision %d, want the namespace's UUID at revision 3", doc.SerialNumber, doc.SerialVersion)
	}
	if doc.Lifecycle != "" {
		t.Fatalf("lifecycle = %q, want none: the phase is the exporting caller's claim", doc.Lifecycle)
	}

	spdxRaw, err := MarshalJSON(doc, TargetSPDX23JSON, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}
	var spdxDoc v23.Document
	if err := json.Unmarshal(spdxRaw, &spdxDoc); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}
	if !strings.HasSuffix(spdxDoc.CreationInfo.CreatorComment, "bomly:document_version=3") {
		t.Errorf("spdx creator comment = %q, want revision 3 restated", spdxDoc.CreationInfo.CreatorComment)
	}
	cdxRaw, err := MarshalJSON(doc, TargetCycloneDX16JSON, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal cyclonedx: %v", err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(cdxRaw, &bom); err != nil {
		t.Fatalf("unmarshal cyclonedx: %v", err)
	}
	if bom.SerialNumber != "urn:uuid:0f3c9a2e-5d4b-4c6a-8e1f-7a2b3c4d5e6f" || bom.Version != 3 {
		t.Errorf("cyclonedx serial %q version %d, want the source's UUID at revision 3", bom.SerialNumber, bom.Version)
	}
	// Having adopted the source's identity, the export does not also link
	// the source: that would be a reference to itself.
	if bom.ExternalReferences != nil {
		t.Errorf("cyclonedx external references = %+v, want none: the source is this document", *bom.ExternalReferences)
	}
	if len(spdxDoc.ExternalDocumentReferences) != 0 {
		t.Errorf("spdx external document refs = %+v, want none: the source is this document", spdxDoc.ExternalDocumentReferences)
	}
}
