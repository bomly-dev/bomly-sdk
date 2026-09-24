package sbom

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bomly-dev/bomly-sdk/internal/testnodes"

	"github.com/bomly-dev/bomly-sdk/model"
)

// An SBOM component whose identity cannot mint a well-formed package URL
// fails the conversion instead of disappearing from it.
//
// This used to `continue`: the component was dropped along with every
// relationship naming it, ToGraph returned no error, and a scan of that
// document reported a smaller graph than the document described. For a tool
// whose answer is "what are you shipping and is it vulnerable", quietly
// returning fewer dependencies than the input listed is the worst available
// failure -- a genuinely vulnerable package can be absent while the scan
// reads clean.
func TestToGraphRefusesAComponentWithNoUsableIdentity(t *testing.T) {
	doc := &Document{
		Components: []Component{
			{ID: "c1", Name: "good", Version: "1.0.0", PURL: "pkg:npm/good@1.0.0"},
			// The maven type requires a namespace; this states one that has
			// none, so the identity is asserted and invalid rather than absent.
			{ID: "c2", Name: "bad", Version: "2.0.0", PURL: "pkg:maven/bad@2.0.0"},
		},
		Dependencies: []Dependency{{Ref: "c1", DependsOn: []string{"c2"}}},
	}

	g, err := ToGraph(doc)
	if err == nil {
		t.Fatalf("ToGraph accepted an unusable identity and returned a graph of %d nodes; "+
			"a dropped component is a dependency missing from the scan", g.Size())
	}
	// The message has to name the offending component: the fix is in the
	// author's document, not here.
	for _, want := range []string{"c2", "pkg:maven/bad@2.0.0"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not name %q", err, want)
		}
	}
}

// A well-formed document still converts, so the refusal is scoped to
// identities that genuinely cannot be minted.
func TestToGraphAcceptsWellFormedComponents(t *testing.T) {
	doc := &Document{
		Components: []Component{
			{ID: "c1", Name: "good", Version: "1.0.0", PURL: "pkg:npm/good@1.0.0"},
			{ID: "c2", Name: "core", Version: "2.0.0", PURL: "pkg:maven/org.acme/core@2.0.0"},
		},
		Dependencies: []Dependency{{Ref: "c1", DependsOn: []string{"c2"}}},
	}

	g, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("ToGraph() error = %v", err)
	}
	if g.Size() != 2 {
		t.Fatalf("graph size = %d, want both components:\n%s", g.Size(), g.PrettyString())
	}
	deps, err := g.DirectDependencies("pkg:npm/good@1.0.0")
	if err != nil {
		t.Fatalf("DirectDependencies() error = %v", err)
	}
	if len(deps) != 1 || deps[0].NodeID() != "pkg:maven/org.acme/core@2.0.0" {
		t.Fatalf("edges = %#v, want the declared relationship preserved", deps)
	}
}

// An SBOM must never name a bom-ref it does not define.
//
// A workspace is module -> child manifest -> child module, and the two edges
// are typed differently: the first derives depends-on, the second describes.
// Publishing the first named the manifest, which is not a component, so
// CycloneDX carried a dependsOn pointing at nothing; filtering the second
// dropped the hop, so the child module came loose from its parent. Both are
// fixed by contracting the path through the structural node.
func TestExportedDependenciesNameOnlyComponents(t *testing.T) {
	g := model.New()
	root := testnodes.Module("package.json", "workspace-root", "1.0.0")
	childManifest := testnodes.Manifest("packages/web/package.json", model.ManifestKindPackageJSON)
	child := testnodes.ModuleFrom("packages/web/package.json", model.Coordinates{
		Ecosystem: "npm", Name: "web", Version: "1.0.0",
	})
	leaf := testnodes.Dep(model.Coordinates{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"})
	for _, node := range []model.GraphNode{root, childManifest, child, leaf} {
		if _, err := g.InsertNode(node); err != nil {
			t.Fatalf("InsertNode(%q): %v", node.NodeID(), err)
		}
	}
	for _, edge := range [][2]string{
		{root.NodeID(), childManifest.NodeID()},
		{childManifest.NodeID(), child.NodeID()},
		{child.NodeID(), leaf.NodeID()},
	} {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("AddEdge(%q -> %q): %v", edge[0], edge[1], err)
		}
	}

	out, err := MarshalDepGraphJSON(g, TargetCycloneDX16JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal cyclonedx: %v", err)
	}
	bom := new(cdx.BOM)
	if err := cdx.NewBOMDecoder(bytes.NewReader(out), cdx.BOMFileFormatJSON).Decode(bom); err != nil {
		t.Fatalf("decode cyclonedx: %v", err)
	}

	refs := map[string]struct{}{}
	if bom.Components != nil {
		for _, component := range *bom.Components {
			refs[component.BOMRef] = struct{}{}
		}
	}
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		refs[bom.Metadata.Component.BOMRef] = struct{}{}
	}
	if _, listed := refs[childManifest.NodeID()]; listed {
		t.Fatalf("the manifest was exported as a component")
	}

	reached := map[string][]string{}
	if bom.Dependencies != nil {
		for _, dependency := range *bom.Dependencies {
			if dependency.Dependencies == nil {
				continue
			}
			for _, ref := range *dependency.Dependencies {
				if _, ok := refs[ref]; !ok {
					t.Fatalf("%q dependsOn %q, which is not a component in this document",
						dependency.Ref, ref)
				}
			}
			reached[dependency.Ref] = *dependency.Dependencies
		}
	}
	// And the workspace path survives the contracted hop.
	if got := reached[root.NodeID()]; len(got) != 1 || got[0] != child.NodeID() {
		t.Fatalf("root dependsOn = %v, want the child module %q reached through the manifest",
			got, child.NodeID())
	}
	if got := reached[child.NodeID()]; len(got) != 1 || got[0] != leaf.NodeID() {
		t.Fatalf("child module dependsOn = %v, want %q", got, leaf.NodeID())
	}
}

// The ingest gates are fixed points, so the values they admit survive every
// further hop.
//
// This is the property bomly-dev/bomly-sdk#54 broke and the SDK's v0.9.5
// NormalizeDescription restored, and it is the reason applyIngestedAssertions
// no longer wraps the gates in a local normalize-until-it-settles loop. The
// input is the shape that found the defect: bytes that are not valid UTF-8,
// short enough to pass the gate's input bound and long enough that repairing
// each of them into U+FFFD -- three bytes apiece -- carries the result past
// that same bound. Under the old gate the first pass returned the repaired,
// over-long value and the second returned "", so a description survived one
// conversion and vanished on the next.
//
// Asserted on the gate itself rather than only through the node, because it
// is the gate's promise; the node assertion below is what the ingest path
// actually depends on.
func TestIngestGatesAreFixedPoints(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		value string
	}{
		{"invalid utf-8 that triples on repair", strings.Repeat("\xff", 5000)},
		{"invalid utf-8 within the bound", strings.Repeat("\xff", 16)},
		{"control characters", "a\x00b\x07c"},
		{"plain text", "a widget for widgets"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			once := model.NormalizeDescription(testCase.value)
			if twice := model.NormalizeDescription(once); twice != once {
				t.Fatalf("NormalizeDescription is not idempotent: %d bytes then %d bytes", len(once), len(twice))
			}

			node, err := model.NewDependencyNode(model.Coordinates{Ecosystem: "npm", Name: "widget", Version: "1.0.0"})
			if err != nil {
				t.Fatalf("construct node: %v", err)
			}
			applyIngestedAssertions(node, Component{Name: "widget", Description: testCase.value})
			if node.Description != once {
				t.Fatalf("ingested description = %q, want the gate's own answer %q", node.Description, once)
			}
			// And a second hop -- export back into a component, ingest again --
			// keeps it, which is what the deleted workaround was protecting.
			second, err := model.NewDependencyNode(model.Coordinates{Ecosystem: "npm", Name: "widget", Version: "1.0.0"})
			if err != nil {
				t.Fatalf("construct node: %v", err)
			}
			applyIngestedAssertions(second, Component{Name: "widget", Description: node.Description})
			if second.Description != node.Description {
				t.Fatalf("description changed on the second hop: %q then %q", node.Description, second.Description)
			}
		})
	}
}

// ToGraph gates a component it is handed directly, not only one a decoder
// produced: a caller can build a Document by hand.
func TestToGraphGatesAHandBuiltComponentCopyright(t *testing.T) {
	doc := &Document{Components: []Component{{
		ID:        "accept",
		Name:      "accept",
		Version:   "1.1.0",
		PURL:      "pkg:npm/accept@1.1.0",
		Copyright: "Copyright\x00 Walmart",
	}}}
	g, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	if got := g.DependencyNodes()[0].Copyright; got != "Copyright Walmart" {
		t.Fatalf("node copyright = %q, want the control character dropped", got)
	}
}

const entryBOM = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
  "components":[
    {"bom-ref":"a","type":"library","name":"a","version":"1.0.0","purl":"pkg:npm/a@1.0.0",
     "properties":[{"name":"bomly:eol","value":"true"},{"name":"bomly:eol_date","value":"2025-01-01"},{"name":"bomly:eol_cycle","value":"1"}]},
    {"bom-ref":"b","type":"library","name":"b","version":"1.0.0","purl":"pkg:npm/b@1.0.0"},
    {"bom-ref":"a2","type":"library","name":"a","version":"1.0.0","purl":"pkg:npm/a@1.0.0"}],
  "vulnerabilities":[{"id":"CVE-2024-0001","source":{"name":"osv"},"description":"bad","cwes":[79],
    "advisories":[{"url":"https://osv.dev/CVE-2024-0001"}],
    "ratings":[{"source":{"name":"osv"},"score":7.5,"severity":"high","method":"CVSSv31","vector":"CVSS:3.1/AV:N"}],
    "analysis":{"state":"not_affected","justification":"code_not_reachable"},
    "affects":[{"ref":"a"},{"ref":"a2"}]}]}`

func TestToGraphEntryCarriesIngestedVulnerabilitiesAndEOL(t *testing.T) {
	doc, _, err := UnmarshalAutoJSON([]byte(entryBOM))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	entry, err := ToGraphEntry(doc, model.ManifestMetadata{Path: "in.cdx.json", Kind: model.ManifestKindSBOM})
	if err != nil {
		t.Fatalf("ToGraphEntry: %v", err)
	}
	if entry.Graph == nil || entry.Graph.Size() != 2 || entry.Document == nil || entry.Manifest.Path != "in.cdx.json" {
		t.Fatalf("entry = %+v", entry)
	}
	// Two components minted one identity and fold into one package; b
	// asserted nothing and gets none.
	if len(entry.Packages) != 1 || entry.Packages[0].PURL != "pkg:npm/a@1.0.0" {
		t.Fatalf("packages = %+v, want one for pkg:npm/a@1.0.0", entry.Packages)
	}
	pkg := entry.Packages[0]
	if len(pkg.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities = %+v, want one", pkg.Vulnerabilities)
	}
	v := pkg.Vulnerabilities[0]
	if v.ID != "CVE-2024-0001" || v.Source != "osv" || v.ParsedSeverity != "high" || v.Details != "bad" ||
		len(v.CVSS) != 1 || v.CVSS[0].Score != 7.5 || v.CVSS[0].Version != "3.1" || len(v.CWEs) != 1 || v.CWEs[0].ID != "CWE-79" ||
		len(v.References) != 1 || v.References[0].Type != model.ReferenceTypeAdvisory ||
		v.Analysis == nil || v.Analysis.State != model.ImpactAnalysisStateNotAffected {
		t.Fatalf("projected vulnerability = %+v", v)
	}
	if pkg.EOL == nil || !pkg.EOL.EOL || pkg.EOL.EOLDate != "2025-01-01" || pkg.EOL.Cycle != "1" || pkg.EOL.Source != "" {
		t.Fatalf("projected eol = %+v", pkg.EOL)
	}

	// Through the graph hop and back out: the registry built from the entry
	// re-emits what the document said.
	registry := model.NewPackageRegistry()
	registry.AddEntryPackages([]model.GraphEntry{entry})
	out, err := MarshalGraphEntriesJSON(entry.Graph, []model.GraphEntry{entry}, TargetCycloneDX16JSON, BuildOptions{Registry: registry, RestatesSource: true, ToolName: "test"}, EncodeOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(out, &bom); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if bom.Vulnerabilities == nil || len(*bom.Vulnerabilities) != 1 {
		t.Fatalf("re-exported vulnerabilities = %+v, want one", bom.Vulnerabilities)
	}
	vuln := (*bom.Vulnerabilities)[0]
	if vuln.ID != "CVE-2024-0001" || vuln.Analysis == nil || vuln.Analysis.Justification != cdx.IAJCodeNotReachable ||
		vuln.Ratings == nil || (*vuln.Ratings)[0].Method != cdx.ScoringMethodCVSSv31 || vuln.Affects == nil || len(*vuln.Affects) != 1 {
		t.Fatalf("re-exported vulnerability = %+v", vuln)
	}
	if !strings.Contains(string(out), `"name":"bomly:eol_date","value":"2025-01-01"`) {
		t.Fatalf("re-exported document lost the end-of-life record: %s", out)
	}
}

func TestToGraphEntryGraphEqualsToGraph(t *testing.T) {
	doc, _, err := UnmarshalAutoJSON([]byte(entryBOM))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	direct, err := ToGraph(doc)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := ToGraphEntry(doc, model.ManifestMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(direct)
	b, _ := json.Marshal(entry.Graph)
	if string(a) != string(b) {
		t.Fatalf("ToGraphEntry's graph differs from ToGraph's:\n%s\n%s", a, b)
	}
	if _, err := ToGraphEntry(nil, model.ManifestMetadata{}); err == nil {
		t.Fatal("nil document accepted")
	}
}
