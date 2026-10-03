package scan

import (
	"testing"

	"github.com/bomly-dev/bomly-sdk/model"
)

func TestCompareReportsDependencyVulnerabilityAndFindingDeltas(t *testing.T) {
	base := &Record{
		Manifests: []Manifest{{Path: "package-lock.json", Dependencies: []Dependency{
			{ID: "pkg:npm/a@1.0.0", DependsOn: []string{"pkg:npm/b@1.0.0"}},
			{ID: "pkg:npm/b@1.0.0"},
			{ID: "pkg:npm/gone@1.0.0"},
			{ID: "module:package.json#pkg:npm/app@1.0.0", DependsOn: []string{"pkg:npm/a@1.0.0"}},
		}}},
		Packages: []*model.Package{{Coordinates: model.Coordinates{PURL: "pkg:npm/b@1.0.0"}, Vulnerabilities: []model.Vulnerability{{ID: "CVE-OLD"}}}},
		Findings: []model.Finding{{ID: "CVE-OLD", PackageRef: "pkg:npm/b@1.0.0"}},
	}
	head := &Record{
		Manifests: []Manifest{{Path: "package-lock.json", Dependencies: []Dependency{
			{ID: "pkg:npm/a@1.0.0", DependsOn: []string{"pkg:npm/b@2.0.0"}},
			{ID: "pkg:npm/b@2.0.0"},
			{ID: "pkg:npm/new@1.0.0"},
		}}},
		Packages: []*model.Package{{Coordinates: model.Coordinates{PURL: "pkg:npm/b@2.0.0"}, Vulnerabilities: []model.Vulnerability{{ID: "CVE-NEW"}}}},
		Findings: []model.Finding{{ID: "CVE-NEW", PackageRef: "pkg:npm/b@2.0.0"}},
	}
	diff, err := Compare(base, head)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Dependencies.Added) != 1 || diff.Dependencies.Added[0].NodeID() != "pkg:npm/new@1.0.0" ||
		len(diff.Dependencies.Removed) != 1 || diff.Dependencies.Removed[0].NodeID() != "pkg:npm/gone@1.0.0" ||
		len(diff.Dependencies.Updated) != 1 || diff.Dependencies.Updated[0].After.NodeID() != "pkg:npm/b@2.0.0" {
		t.Fatalf("dependency diff = %+v", diff.Dependencies)
	}
	if len(diff.AddedVulnerabilities) != 1 || diff.AddedVulnerabilities[0] != (VulnerabilityRef{"pkg:npm/b@2.0.0", "CVE-NEW"}) ||
		len(diff.RemovedVulnerabilities) != 1 || diff.RemovedVulnerabilities[0] != (VulnerabilityRef{"pkg:npm/b@1.0.0", "CVE-OLD"}) {
		t.Fatalf("vulnerability delta = %+v / %+v", diff.AddedVulnerabilities, diff.RemovedVulnerabilities)
	}
	if len(diff.AddedFindings) != 1 || diff.AddedFindings[0] != (FindingRef{ID: "CVE-NEW", PackageRef: "pkg:npm/b@2.0.0"}) ||
		len(diff.RemovedFindings) != 1 || diff.RemovedFindings[0] != (FindingRef{ID: "CVE-OLD", PackageRef: "pkg:npm/b@1.0.0"}) {
		t.Fatalf("finding delta = %+v / %+v", diff.AddedFindings, diff.RemovedFindings)
	}
	if _, err := Compare(base, nil); err == nil {
		t.Fatal("nil head accepted")
	}
	if _, err := Compare(&Record{Manifests: []Manifest{{Dependencies: []Dependency{{ID: "pkg:not a purl"}}}}}, head); err == nil {
		t.Fatal("an unmintable identity was accepted")
	}
}

// A record may spell a package URL in a form the model canonicalizes when
// it mints the node's identity; an edge named in the record's spelling
// must still land on the node.
func TestCompareResolvesEdgesThroughCanonicalIDs(t *testing.T) {
	base := &Record{Manifests: []Manifest{{Path: "package-lock.json", Dependencies: []Dependency{
		{ID: "pkg:NPM/a@1.0.0", DependsOn: []string{"pkg:NPM/b@1.0.0"}},
		{ID: "pkg:NPM/b@1.0.0"},
	}}}}
	g, err := graphOf(base)
	if err != nil {
		t.Fatalf("graphOf: %v", err)
	}
	if g.Size() != 2 {
		t.Fatalf("graph has %d nodes, want 2", g.Size())
	}
	if _, ok := g.Node("pkg:npm/a@1.0.0"); !ok {
		t.Fatal("the canonical identity is not in the graph")
	}
	children, err := g.DirectDependencies("pkg:npm/a@1.0.0")
	if err != nil || len(children) != 1 || children[0].NodeID() != "pkg:npm/b@1.0.0" {
		t.Fatalf("direct dependencies of a = %v, %v; want the one edge the record named", children, err)
	}
}

// A dependency is direct when it hangs off a module, so the module and its
// edges are rebuilt from the record: without them every root reads as
// direct and a transitive dependency that became direct goes unreported.
func TestCompareReportsATransitiveDependencyBecomingDirect(t *testing.T) {
	module := Dependency{ID: "module:package.json#pkg:npm/app@1.0.0", Name: "app", Version: "1.0.0", PURL: "pkg:npm/app@1.0.0", DependsOn: []string{"pkg:npm/a@1.0.0"}}
	base := &Record{Manifests: []Manifest{{Path: "package.json", Dependencies: []Dependency{
		module,
		{ID: "pkg:npm/a@1.0.0", DependsOn: []string{"pkg:npm/b@1.0.0"}},
		{ID: "pkg:npm/b@1.0.0"},
	}}}}
	head := &Record{Manifests: []Manifest{{Path: "package.json", Dependencies: []Dependency{
		{ID: module.ID, Name: module.Name, Version: module.Version, PURL: module.PURL, DependsOn: []string{"pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0"}},
		{ID: "pkg:npm/a@1.0.0", DependsOn: []string{"pkg:npm/b@1.0.0"}},
		{ID: "pkg:npm/b@1.0.0"},
	}}}}
	diff, err := Compare(base, head)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, transition := range diff.Dependencies.Transitions {
		if transition.After != nil && transition.After.NodeID() == "pkg:npm/b@1.0.0" &&
			transition.BeforeRelationship == model.DependencyRelationshipTransitive && transition.AfterRelationship == model.DependencyRelationshipDirect {
			found = true
		}
	}
	if !found {
		t.Fatalf("transitive-to-direct change not reported: %+v", diff.Dependencies.Transitions)
	}
}

// A dependency's source travels with the record, so a package that moved
// from a registry to Git between scans is reported as the review-worthy
// transition it is.
func TestCompareReportsASourceTransition(t *testing.T) {
	base := &Record{Manifests: []Manifest{{Path: "package.json", Dependencies: []Dependency{{ID: "pkg:npm/a@1.0.0", Source: model.DependencySourceRegistry}}}}}
	head := &Record{Manifests: []Manifest{{Path: "package.json", Dependencies: []Dependency{{ID: "pkg:npm/a@1.0.0", Source: model.DependencySourceGit}}}}}
	diff, err := Compare(base, head)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, transition := range diff.Dependencies.Transitions {
		for _, field := range transition.ChangedFields {
			if field == model.DependencyDetailSource {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("source transition not reported: %+v", diff.Dependencies.Transitions)
	}
}

// A finding's identity for the comparison is the one Encode orders by: a
// vulnerability finding replaced by a policy finding under the same ID on
// the same package is one removed and one added, not nothing.
func TestCompareDistinguishesFindingsByKindVulnerabilityAndRule(t *testing.T) {
	base := &Record{Findings: []model.Finding{{ID: "X", PackageRef: "pkg:npm/a@1.0.0", Kind: model.FindingKindVulnerability, VulnerabilityID: "X"}}}
	head := &Record{Findings: []model.Finding{{ID: "X", PackageRef: "pkg:npm/a@1.0.0", Kind: model.FindingKindPackage, RuleID: "denied"}}}
	diff, err := Compare(base, head)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.AddedFindings) != 1 || diff.AddedFindings[0].RuleID != "denied" || len(diff.RemovedFindings) != 1 || diff.RemovedFindings[0].VulnerabilityID != "X" {
		t.Fatalf("finding delta = %+v / %+v", diff.AddedFindings, diff.RemovedFindings)
	}
}
