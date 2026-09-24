package scan

import (
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
