package sbom

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	v30 "github.com/spdx/tools-golang/spdx/v3/v3_0"

	"github.com/bomly-dev/bomly-sdk/model"
)

// richSPDX3Document exercises everything the SPDX 3 codec carries: scopes in
// both directions, a declared and a concluded license with a WITH clause, a
// custom license with text, digests including a SHA3 one, a CPE, a supplier
// shared by two packages, a second origin, an asserted reference outside the
// converter's vocabulary, an advisory, and the document-level lifecycle.
func richSPDX3Document() *Document {
	return &Document{
		Name:        "rich",
		Namespace:   "https://bomly.dev/spdx/1b4e28ba-2fa1-11d2-883f-0016d3cca427",
		Tool:        "bomly-cli",
		ToolVersion: "0.31.0",
		Created:     time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC),
		Lifecycle:   "build",
		Components: []Component{
			{ID: "DocumentRoot-app", Name: "app", Version: "1.0.0", Type: "application"},
			{
				ID: "pkg:npm/%40scope/left-pad@1.3.0", Name: "left-pad", Org: "@scope", Version: "1.3.0",
				PURL:   "pkg:npm/%40scope/left-pad@1.3.0",
				Scopes: model.ScopesOf("runtime", "development"),
				Licenses: []License{
					{Value: "MIT", SPDXExpression: "MIT"},
					{Value: "Apache-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0", SPDXExpression: "Apache-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0", Type: "concluded"},
				},
				Digests: []Digest{
					{Algorithm: "sha256", Value: strings.Repeat("ab", 32)},
					{Algorithm: "sha3-256", Value: strings.Repeat("cd", 32)},
				},
				CPEs:        []string{"cpe:2.3:a:left-pad:left-pad:1.3.0:*:*:*:*:*:*:*"},
				Supplier:    &model.Contact{Kind: model.ContactKindOrganization, Name: "Acme"},
				Description: "pads strings",
				Homepage:    "https://left-pad.example/home",
				ArtifactURL: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
				Origins: []ComponentOrigin{
					{ArtifactURL: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
					{ArtifactURL: "https://mirror.example/left-pad-1.3.0.tgz"},
				},
				ExternalReferences: []model.ExternalReference{
					{Category: model.ExternalReferenceCategoryOther, Type: "website", Locator: "https://left-pad.example", Comment: "project site"},
				},
				Vulnerabilities: []Vulnerability{{ID: "GHSA-aaaa-bbbb-cccc", Advisories: []string{"https://github.com/advisories/GHSA-aaaa-bbbb-cccc"}}},
				EOL:             &EOL{EOL: true, EOLDate: "2025-01-31"},
			},
			{
				ID: "pkg:npm/custom@2.0.0", Name: "custom", Version: "2.0.0", PURL: "pkg:npm/custom@2.0.0",
				Supplier: &model.Contact{Kind: model.ContactKindOrganization, Name: "Acme"},
				Licenses: []License{
					{Value: "Some custom license text"},
					{Value: "MIT", SPDXExpression: "MIT", Type: "concluded"},
				},
			},
		},
		Dependencies: []Dependency{
			{Ref: "DocumentRoot-app", DependsOn: []string{"pkg:npm/%40scope/left-pad@1.3.0", "pkg:npm/custom@2.0.0"}},
			{Ref: "pkg:npm/%40scope/left-pad@1.3.0", DependsOn: []string{"pkg:npm/custom@2.0.0"}},
		},
		Roots: []string{"DocumentRoot-app"},
	}
}

// spdx3DocumentImports reads the documents an SPDX 3 document imports -- the
// form ADR-0042's source links take in SPDX 3.
func spdx3DocumentImports(t *testing.T, raw []byte) []struct {
	ExternalSpdxID string `json:"externalSpdxId"`
	LocationHint   string `json:"locationHint"`
} {
	t.Helper()
	var doc struct {
		Graph []json.RawMessage `json:"@graph"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode spdx 3 document: %v\n%s", err, raw)
	}
	for _, node := range doc.Graph {
		var element struct {
			Type    string `json:"type"`
			Imports []struct {
				ExternalSpdxID string `json:"externalSpdxId"`
				LocationHint   string `json:"locationHint"`
			} `json:"import"`
		}
		if err := json.Unmarshal(node, &element); err != nil {
			t.Fatalf("decode spdx 3 element: %v", err)
		}
		if element.Type == "SpdxDocument" {
			out := make([]struct {
				ExternalSpdxID string `json:"externalSpdxId"`
				LocationHint   string `json:"locationHint"`
			}, len(element.Imports))
			copy(out, element.Imports)
			return out
		}
	}
	t.Fatalf("no SpdxDocument element in\n%s", raw)
	return nil
}

// spdx3GraphNodes returns the @graph nodes of an SPDX 3 document.
func spdx3GraphNodes(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	var doc struct {
		Graph []map[string]any `json:"@graph"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode spdx 3 document: %v\n%s", err, raw)
	}
	return doc.Graph
}

func spdx3NodesOfType(t *testing.T, raw []byte, typ string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, node := range spdx3GraphNodes(t, raw) {
		if node["type"] == typ {
			out = append(out, node)
		}
	}
	return out
}

// The library's own validation accepts what the encoder writes, read back
// with the library's own reader.
func TestSPDX3OutputPassesTheLibraryValidation(t *testing.T) {
	raw, err := MarshalJSON(richSPDX3Document(), TargetSPDX30JSON, EncodeOptions{Pretty: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	var reread v30.Document
	if err := reread.FromJSON(bytes.NewReader(raw)); err != nil {
		t.Fatalf("the library cannot read the export: %v\n%s", err, raw)
	}
	// preProcess, because the reader resolves the specification's
	// individual license values to the library's shared instances, which
	// carry no creation info of their own; preProcess applies the library's
	// fill-ins, the same ones the encoder ran before writing.
	if err := reread.Validate(true); err != nil {
		t.Fatalf("the library rejects the export: %v\n%s", err, raw)
	}
}

// One document, written twice, is the same bytes. The library's converter and
// serializer both iterate maps; before nameSPDX3Elements and
// canonicalSPDX3JSON, every run produced a different element order and
// different minted identifiers for the same relationships and licenses.
func TestSPDX3EncodingIsDeterministic(t *testing.T) {
	first, err := MarshalJSON(richSPDX3Document(), TargetSPDX30JSON, EncodeOptions{Pretty: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	for run := 0; run < 20; run++ {
		again, err := MarshalJSON(richSPDX3Document(), TargetSPDX30JSON, EncodeOptions{Pretty: true})
		if err != nil {
			t.Fatalf("export %d: %v", run, err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("export %d differs from the first:\nfirst:\n%s\nagain:\n%s", run, first, again)
		}
	}
}

// Encoding does not mutate the library's shared license values. ToJSON writes
// the document's creation info into any element without one, and
// NoAssertionLicense is a package variable: publishing it directly leaked one
// document's creation info into every later document in the process.
func TestSPDX3EncodingLeavesTheLibrarySingletonsAlone(t *testing.T) {
	singletons := []v30.AnyIndividualLicensingInfo{
		v30.IndividualLicensingInfo_NoAssertionLicense,
		v30.IndividualLicensingInfo_NoneLicense,
	}
	// Cleared for the duration, because ToJSON fills only a nil creation
	// info: once anything in this process -- another test running the
	// library's own fill-ins -- has set one, a regression here would leave
	// no trace.
	for _, singleton := range singletons {
		previous := singleton.GetCreationInfo()
		singleton.SetCreationInfo(nil)
		t.Cleanup(func() { singleton.SetCreationInfo(previous) })
	}
	for _, created := range []time.Time{
		time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2002, 2, 2, 0, 0, 0, 0, time.UTC),
	} {
		doc := richSPDX3Document()
		doc.Created = created
		raw, err := MarshalJSON(doc, TargetSPDX30JSON, EncodeOptions{})
		if err != nil {
			t.Fatalf("export: %v", err)
		}
		if infos := spdx3NodesOfType(t, raw, "CreationInfo"); len(infos) != 1 {
			t.Fatalf("creation info nodes = %d, want one\n%s", len(infos), raw)
		}
	}
	for _, singleton := range singletons {
		if singleton.GetCreationInfo() != nil {
			t.Errorf("%s was given a creation info by an encode", singleton.GetID())
		}
	}
}

// A decoded SPDX 3 export says what a decoded SPDX 2.3 export of the same
// document says. Both are read by documentFromSPDX23, so any difference is
// something the 3.0 conversion or its inverse lost.
func TestSPDX3RoundTripMatchesSPDX23(t *testing.T) {
	decode := func(target Target) *Document {
		t.Helper()
		raw, err := MarshalJSON(richSPDX3Document(), target, EncodeOptions{})
		if err != nil {
			t.Fatalf("export %s: %v", target, err)
		}
		doc, err := UnmarshalJSON(raw, target)
		if err != nil {
			t.Fatalf("ingest %s: %v\n%s", target, err, raw)
		}
		// Each document's own bytes and format differ by definition.
		doc.Assertions.Checksum = nil
		doc.Assertions.Format = ""
		return doc
	}
	want := decode(TargetSPDX23JSON)
	got := decode(TargetSPDX30JSON)

	if !reflect.DeepEqual(got.Components, want.Components) {
		for i := range want.Components {
			if i < len(got.Components) && !reflect.DeepEqual(got.Components[i], want.Components[i]) {
				t.Errorf("component %d:\n spdx 3:   %+v\n spdx 2.3: %+v", i, got.Components[i], want.Components[i])
			}
		}
		if len(got.Components) != len(want.Components) {
			t.Errorf("components = %d, want %d", len(got.Components), len(want.Components))
		}
	}
	for _, field := range []struct {
		name      string
		got, want any
	}{
		{"dependencies", got.Dependencies, want.Dependencies},
		{"roots", got.Roots, want.Roots},
		{"described", got.Described, want.Described},
		{"name", got.Name, want.Name},
		{"namespace", got.Namespace, want.Namespace},
		{"tools", got.Tools, want.Tools},
		{"created", got.Created, want.Created},
		{"lifecycle", got.Lifecycle, want.Lifecycle},
		{"serial version", got.SerialVersion, want.SerialVersion},
		{"assertions", got.Assertions, want.Assertions},
	} {
		if !reflect.DeepEqual(field.got, field.want) {
			t.Errorf("%s:\n spdx 3:   %+v\n spdx 2.3: %+v", field.name, field.got, field.want)
		}
	}
}

// Every digest the SDK publishes in SPDX 2.3 is published in SPDX 3 and read
// back. The pinned library's converter misspells the SHA3 and BLAKE2b
// algorithms and wrote those hashes with an empty, required algorithm;
// prepareSPDX23ForConversion corrects it. This runs over the SDK's whole
// registry, so a new algorithm, or a library release that changes the
// spelling, fails here by name.
func TestSPDX3PublishesEveryDigestTheSDKPublishes(t *testing.T) {
	for _, algorithm := range model.DigestAlgorithms() {
		if algorithm.SPDXName() == "" {
			continue
		}
		t.Run(string(algorithm), func(t *testing.T) {
			value, ok := publishableDigestValue(algorithm)
			if !ok {
				t.Skipf("the SDK publishes no value for %s at any common length", algorithm)
			}
			doc := &Document{
				Name: "digest",
				Components: []Component{{
					ID: "pkg:npm/widget@1.0.0", Name: "widget", Version: "1.0.0", PURL: "pkg:npm/widget@1.0.0",
					Digests: []Digest{{Algorithm: string(algorithm), Value: value}},
				}},
			}
			want := roundTripDigests(t, doc, TargetSPDX23JSON)
			if len(want) == 0 {
				t.Skipf("the SDK does not publish %s in SPDX 2.3 either", algorithm)
			}
			if got := roundTripDigests(t, doc, TargetSPDX30JSON); !reflect.DeepEqual(got, want) {
				t.Errorf("spdx 3 digests = %+v, want %+v as spdx 2.3 reads them", got, want)
			}
		})
	}
}

func publishableDigestValue(algorithm model.DigestAlgorithm) (string, bool) {
	for _, length := range []int{8, 32, 40, 56, 64, 96, 128} {
		value := strings.Repeat("a", length)
		if _, ok := (model.Digest{Algorithm: algorithm, Value: value}).Normalized(); ok {
			return value, true
		}
	}
	return "", false
}

func roundTripDigests(t *testing.T, doc *Document, target Target) []Digest {
	t.Helper()
	raw, err := MarshalJSON(doc, target, EncodeOptions{})
	if err != nil {
		t.Fatalf("export %s: %v", target, err)
	}
	back, err := UnmarshalJSON(raw, target)
	if err != nil {
		t.Fatalf("ingest %s: %v\n%s", target, err, raw)
	}
	return componentNamed(t, back, "widget").Digests
}

// The inverse vocabulary is derived from the library's forward converter, not
// written here. This pins what the derivation finds against the SDK registry
// and tools-golang's 2.3 constants, so a library release that maps more (or
// less) shows up as a named failure.
func TestSPDX3VocabularyIsDerivedFromTheLibrary(t *testing.T) {
	vocabulary := deriveSPDX3Vocabulary()

	var spdxNamed []string
	for _, algorithm := range model.DigestAlgorithms() {
		if name := algorithm.SPDXName(); name != "" {
			spdxNamed = append(spdxNamed, name)
		}
	}
	var derived []string
	for _, spelling := range vocabulary.checksums {
		derived = append(derived, string(spelling))
	}
	slices.Sort(spdxNamed)
	slices.Sort(derived)
	if !slices.Equal(derived, spdxNamed) {
		t.Errorf("hash algorithms derived = %v, want every SDK algorithm with an SPDX name: %v", derived, spdxNamed)
	}

	// The Annex F types the pinned converter does not map for a package.
	// When the library learns one, this list shrinks.
	unmapped := map[string]bool{"swh": true, "gitoid": true}
	found := map[string]bool{}
	for _, term := range vocabulary.references {
		found[term.refType] = true
	}
	for _, term := range spdx3AnnexFReferenceTypes {
		switch {
		case unmapped[term.refType] && found[term.refType]:
			t.Errorf("the library now converts %s; remove it from the unmapped list", term.refType)
		case !unmapped[term.refType] && !found[term.refType]:
			t.Errorf("no SPDX 3 type was derived for %s %s", term.category, term.refType)
		}
	}
}

// What From_v2_3 drops is carried: an origin beyond the first as an
// alternative download location, and an asserted reference outside the
// converter's vocabulary as an "other" reference that reads back with its 2.3
// category, type and comment.
func TestSPDX3CarriesReferencesTheConverterDrops(t *testing.T) {
	raw, err := MarshalJSON(richSPDX3Document(), TargetSPDX30JSON, EncodeOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"altDownloadLocation"`)) || !bytes.Contains(raw, []byte("https://mirror.example/left-pad-1.3.0.tgz")) {
		t.Errorf("the second origin was dropped:\n%s", raw)
	}
	back, err := UnmarshalJSON(raw, TargetSPDX30JSON)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	refs := componentNamed(t, back, "left-pad").ExternalReferences
	var website *model.ExternalReference
	for i := range refs {
		if refs[i].Type == "website" {
			website = &refs[i]
		}
		// The origin is published, and declined on the way back in, as the
		// 2.3 and CycloneDX readers decline theirs.
		if strings.Contains(refs[i].Locator, "mirror.example") {
			t.Errorf("an origin came back as a source assertion: %+v", refs[i])
		}
	}
	if website == nil {
		t.Fatalf("the website reference was dropped: %+v\n%s", refs, raw)
	}
	if website.Category != model.ExternalReferenceCategoryOther || website.Locator != "https://left-pad.example" || website.Comment != "project site" {
		t.Errorf("website reference = %+v", *website)
	}
}

// SPDX 3 requires a createdBy agent. A scan credited to the tool alone gets
// its producing tool as a software agent rather than an invalid document; the
// tools its sources credited stay tools.
func TestSPDX3CreditsTheToolAsTheCreatingAgent(t *testing.T) {
	doc := richSPDX3Document()
	doc.Assertions.Tools = []model.DocumentTool{{Name: "upstream-generator-2.0"}}
	raw, err := MarshalJSON(doc, TargetSPDX30JSON, EncodeOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	agents := spdx3NodesOfType(t, raw, "SoftwareAgent")
	if len(agents) != 1 || agents[0]["name"] != "bomly-cli-0.31.0" {
		t.Errorf("software agents = %v, want the tool", agents)
	}
	back, err := UnmarshalJSON(raw, TargetSPDX30JSON)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if got := len(spdx3NodesOfType(t, raw, "Tool")); got != 2 {
		t.Errorf("tools = %d, want the producer and the source's generator", got)
	}
	if len(back.Assertions.Creators) != 0 || len(back.Assertions.Tools) != 2 {
		t.Errorf("each tool should read back once, as a tool: creators %+v tools %+v", back.Assertions.Creators, back.Assertions.Tools)
	}
}

// A shared supplier and a shared license are published once each.
func TestSPDX3FoldsSharedAgentsAndLicenses(t *testing.T) {
	raw, err := MarshalJSON(richSPDX3Document(), TargetSPDX30JSON, EncodeOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if got := len(spdx3NodesOfType(t, raw, "Organization")); got != 1 {
		t.Errorf("organizations = %d, want Acme once", got)
	}
	mit := 0
	for _, license := range spdx3NodesOfType(t, raw, "expandedlicensing_ListedLicense") {
		if license["name"] == "MIT" {
			mit++
		}
	}
	if mit != 1 {
		t.Errorf("MIT published %d times, want once\n%s", mit, raw)
	}
}

// Detection reads the format's own declaration, its JSON-LD context, in
// either of the forms JSON-LD allows.
func TestSPDX3DetectionReadsTheContext(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want Target
	}{
		{"string context", `{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[{}]}`, TargetSPDX30JSON},
		{"list context", `{"@context":["https://spdx.org/rdf/3.0.1/spdx-context.jsonld",{"x":"y"}],"@graph":[{}]}`, TargetSPDX30JSON},
		{"no graph", `{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}`, ""},
		{"empty graph", `{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[]}`, ""},
		{"graph not a list", `{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":{}}`, ""},
		{"another context", `{"@context":"https://schema.org","@graph":[{}]}`, ""},
		{"context not a string", `{"@context":7,"@graph":[{}]}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DetectJSONTarget([]byte(tc.raw))
			if tc.want == "" {
				if !errors.Is(err, ErrUnsupportedFormat) {
					t.Errorf("DetectJSONTarget = %q, %v; want ErrUnsupportedFormat", got, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Errorf("DetectJSONTarget = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// A document another producer wrote -- full IRIs, a License List IRI, a
// lifecycle-scoped dependency, a purl given only as an identifier, a simple
// licensing expression -- reads into the same model a 2.3 document would.
func TestSPDX3ReadsADocumentBomlyDidNotWrite(t *testing.T) {
	raw, err := os.ReadFile("testdata/spdx3/foreign.spdx3.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	doc, target, err := UnmarshalAutoJSON(raw)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if target != TargetSPDX30JSON {
		t.Fatalf("target = %q, want spdx 3", target)
	}
	if doc.Name != "app-sbom" || doc.Namespace != "https://example.com/docs/app-1" || doc.Assertions.Comment != "produced by another tool" {
		t.Errorf("document = name %q namespace %q comment %q", doc.Name, doc.Namespace, doc.Assertions.Comment)
	}
	if !doc.Created.Equal(time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Errorf("created = %v", doc.Created)
	}
	if len(doc.Assertions.Tools) != 1 || doc.Assertions.Tools[0].Name != "examplegen-1.2.0" {
		t.Errorf("tools = %+v", doc.Assertions.Tools)
	}
	if len(doc.Assertions.Creators) != 1 || doc.Assertions.Creators[0].Name != "Acme Corp" {
		t.Errorf("creators = %+v", doc.Assertions.Creators)
	}

	app := componentNamed(t, doc, "app")
	if app.Type != "application" {
		t.Errorf("app type = %q", app.Type)
	}
	if len(doc.Roots) != 1 || doc.Roots[0] != app.ID {
		t.Errorf("roots = %v, want the SBOM's root element %q", doc.Roots, app.ID)
	}
	var appDeps []string
	for _, dep := range doc.Dependencies {
		if dep.Ref == app.ID {
			appDeps = dep.DependsOn
		}
	}
	lodash := componentNamed(t, doc, "lodash")
	jest := componentNamed(t, doc, "jest")
	if !slices.Contains(appDeps, lodash.ID) || !slices.Contains(appDeps, jest.ID) {
		t.Errorf("app depends on %v, want lodash %q and jest %q (the latter lifecycle-scoped)", appDeps, lodash.ID, jest.ID)
	}

	if lodash.PURL != "pkg:npm/lodash@4.17.21" {
		t.Errorf("lodash purl = %q", lodash.PURL)
	}
	if lodash.Supplier == nil || lodash.Supplier.Name != "Acme Corp" {
		t.Errorf("lodash supplier = %+v", lodash.Supplier)
	}
	if len(lodash.Digests) != 1 || !strings.EqualFold(lodash.Digests[0].Algorithm, "SHA512") {
		t.Errorf("lodash digests = %+v", lodash.Digests)
	}
	if len(lodash.Licenses) != 1 || lodash.Licenses[0].SPDXExpression != "MIT" || lodash.Licenses[0].Type != string(model.LicenseTypeDeclared) {
		t.Errorf("lodash licenses = %+v, want MIT declared through its License List IRI", lodash.Licenses)
	}
	var tracker bool
	for _, ref := range lodash.ExternalReferences {
		tracker = tracker || (ref.Type == "issueTracker" && ref.Locator == "https://github.com/lodash/lodash/issues")
	}
	if !tracker {
		t.Errorf("lodash references = %+v, want the issue tracker under its SPDX 3 name", lodash.ExternalReferences)
	}

	if jest.PURL != "pkg:npm/jest@29.0.0" {
		t.Errorf("jest purl = %q, want the one given as an external identifier", jest.PURL)
	}
	if len(jest.Licenses) != 1 || jest.Licenses[0].SPDXExpression != "MIT OR Apache-2.0" || jest.Licenses[0].Type != string(model.LicenseTypeConcluded) {
		t.Errorf("jest licenses = %+v", jest.Licenses)
	}
}

// The library's reader panics on some malformed graphs; ingest reports them
// as malformed input instead of crashing the scan.
func TestSPDX3DecodeContainsLibraryPanics(t *testing.T) {
	// A vocabulary value written as an element of the graph, the shape that
	// made the reader panic on the converter's own pre-fix output.
	raw := `{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[` +
		`{"type":"CreationInfo","@id":"_:c","specVersion":"3.0.1","created":"2025-01-01T00:00:00Z","createdBy":[]},` +
		`{"type":"SpdxDocument","spdxId":"https://example.com/d","creationInfo":"_:c"},` +
		`{"type":"software_Package","spdxId":"https://example.com/p","name":"p","creationInfo":"_:c",` +
		`"verifiedUsing":[{"type":"Hash","algorithm":"https://example.com/h","hashValue":"00"}]},` +
		`{"type":"HashAlgorithm","spdxId":"https://example.com/h"}]}`
	_, err := UnmarshalJSON([]byte(raw), TargetSPDX30JSON)
	if err == nil {
		t.Skip("the library now reads this graph without failing; the recover is still the boundary")
	}
	if !errors.Is(err, ErrMalformedJSON) {
		t.Errorf("err = %v, want ErrMalformedJSON", err)
	}
}
