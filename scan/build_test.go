package scan

import (
	"encoding/json"
	"testing"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/testkit"
)

// workspace builds module -> child manifest -> child module -> dependency,
// the shape whose middle manifest a record must step through.
func workspace(t *testing.T) *model.Graph {
	t.Helper()
	g := model.New()
	root := testkit.MustManifestNode(t, "package.json", model.ManifestKindPackageLockJSON)
	rootModule := testkit.MustModuleNode(t, "package.json", model.Coordinates{Ecosystem: model.EcosystemNPM, Name: "app", Version: "1.0.0"})
	child := testkit.MustManifestNode(t, "packages/ui/package.json", model.ManifestKindPackageLockJSON)
	childModule := testkit.MustModuleNode(t, "packages/ui/package.json", model.Coordinates{Ecosystem: model.EcosystemNPM, Name: "ui", Version: "1.0.0"})
	dep := testkit.MustDependencyFrom(t, model.DependencyNode{
		Coordinates: model.Coordinates{Ecosystem: model.EcosystemNPM, Name: "react", Version: "18.2.0"},
		Scopes:      []model.Scope{model.ScopeRuntime},
		Matched:     true,
		Licenses:    []model.PackageLicense{{Value: "MIT", SPDXExpression: "MIT"}},
	})
	for _, node := range []model.GraphNode{root, rootModule, child, childModule, dep} {
		if err := g.AddNode(node); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range [][2]string{{root.NodeID(), rootModule.NodeID()}, {rootModule.NodeID(), child.NodeID()}, {child.NodeID(), childModule.NodeID()}, {childModule.NodeID(), dep.NodeID()}} {
		if err := g.AddEdge(e[0], e[1]); err != nil {
			t.Fatal(err)
		}
	}
	return g
}

func TestFromGraphEntriesStepsThroughManifestNodes(t *testing.T) {
	g := workspace(t)
	registry := model.NewPackageRegistry()
	registry.Ensure("pkg:npm/react@18.2.0").Vulnerabilities = []model.Vulnerability{{ID: "CVE-1"}}
	findings := []model.Finding{{ID: "CVE-1", Kind: model.FindingKindVulnerability, PackageRef: "pkg:npm/react@18.2.0", Severity: "high", PolicyStatus: model.FindingPolicyStatusFail}}
	r := FromGraphEntries([]model.GraphEntry{{Graph: g, Manifest: model.ManifestMetadata{Path: "package.json", Kind: model.ManifestKindPackageLockJSON}}}, registry, findings)
	if len(r.Manifests) != 1 || r.Manifests[0].Path != "package.json" {
		t.Fatalf("manifests = %+v", r.Manifests)
	}
	deps := map[string]Dependency{}
	for _, d := range r.Manifests[0].Dependencies {
		deps[d.ID] = d
		if d.ID[:9] == "manifest:" {
			t.Fatalf("a manifest node was listed: %s", d.ID)
		}
	}
	if len(deps) != 3 {
		t.Fatalf("dependencies = %d, want two modules and one dependency", len(deps))
	}
	rootModule := deps["module:package.json#pkg:npm/app@1.0.0"]
	if len(rootModule.DependsOn) != 1 || rootModule.DependsOn[0] != "module:packages/ui/package.json#pkg:npm/ui@1.0.0" {
		t.Fatalf("root module edges = %v, want the child module through its manifest", rootModule.DependsOn)
	}
	react := deps["pkg:npm/react@18.2.0"]
	if react.PURL != "pkg:npm/react@18.2.0" || !react.Matched || len(react.Scopes) != 1 || len(react.Licenses) != 1 || react.PackageRef != "pkg:npm/react@18.2.0" {
		t.Fatalf("dependency projection = %+v", react)
	}
	if len(r.Packages) != 1 || r.Packages[0].PURL != "pkg:npm/react@18.2.0" || len(r.Findings) != 1 {
		t.Fatalf("packages/findings = %+v / %+v", r.Packages, r.Findings)
	}
	if r.AuditSummary == nil || r.AuditSummary.High != 1 || r.AuditSummary.Total != 1 {
		t.Fatalf("summary = %+v", r.AuditSummary)
	}
	if r.Subject != (Subject{}) || r.Verdict != "" {
		t.Fatal("the builder must leave subject and verdict to the caller")
	}
	if VerdictOf(findings) != VerdictFail || VerdictOf(nil) != VerdictPass ||
		VerdictOf([]model.Finding{{PolicyStatus: model.FindingPolicyStatusWarn}}) != VerdictWarn || VerdictOf([]model.Finding{{}}) != VerdictFail {
		t.Fatal("VerdictOf")
	}
	if _, err := Encode(r); err != nil {
		t.Fatal(err)
	}
}

// The bands are the model's ranks, so the aliases it equates land where
// they rank rather than in unknown.
func TestSummarizeCountsSeverityAliasesInTheirBands(t *testing.T) {
	got := summarize([]model.Finding{
		{Severity: model.SeverityCritical}, {Severity: model.SeverityError}, {Severity: model.SeverityWarning},
		{Severity: model.SeverityNote}, {Severity: " HIGH "}, {Severity: "bogus"}, {},
	})
	want := &AuditSummary{Critical: 1, High: 2, Medium: 1, Low: 1, Unknown: 2, Total: 7}
	if *got != *want {
		t.Fatalf("summary = %+v, want %+v", got, want)
	}
}

// A status outside the vocabulary must not read as gentler than fail,
// whether it arrived through the codec, which clears it, or was set in
// process.
func TestVerdictOfFailsClosedOnAnUnknownStatus(t *testing.T) {
	if got := VerdictOf([]model.Finding{{ID: "x", PolicyStatus: "allow"}}); got != VerdictFail {
		t.Fatalf("verdict with an unknown status = %q, want fail", got)
	}
	var decoded model.Finding
	if err := json.Unmarshal([]byte(`{"id":"x","kind":"vulnerability","policy_status":"allow"}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.PolicyStatus != "" || VerdictOf([]model.Finding{decoded}) != VerdictFail {
		t.Fatalf("decoded status = %q; the codec must clear an unknown status and the verdict must fail", decoded.PolicyStatus)
	}
	if got := VerdictOf([]model.Finding{{ID: "x", PolicyStatus: model.FindingPolicyStatusWarn}, {ID: "y", PolicyStatus: model.FindingPolicyStatusSuppressed}}); got != VerdictWarn {
		t.Fatalf("verdict with warn and suppressed = %q, want warn", got)
	}
}

// An ingested document's own assertions ride on its manifest, so a record
// restates the document's provenance and not only its contents.
func TestFromGraphEntriesCarriesTheDocumentAssertions(t *testing.T) {
	entry := model.GraphEntry{Manifest: model.ManifestMetadata{Path: "sbom.cdx.json", Kind: model.ManifestKindSBOM}, Graph: model.New(),
		Document: &model.DocumentAssertions{Identity: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", Format: "cyclonedx-1.6+json"}}
	r := FromGraphEntries([]model.GraphEntry{entry}, nil, nil)
	if len(r.Manifests) != 1 || r.Manifests[0].Document == nil || r.Manifests[0].Document.Format != "cyclonedx-1.6+json" {
		t.Fatalf("manifests = %+v, want the document assertions on the manifest", r.Manifests)
	}
	data, err := Encode(r)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Manifests[0].Document == nil || decoded.Manifests[0].Document.Identity != entry.Document.Identity {
		t.Fatalf("document assertions did not survive the record: %+v", decoded.Manifests[0].Document)
	}
}
