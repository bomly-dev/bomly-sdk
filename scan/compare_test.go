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
	if len(diff.AddedFindings) != 1 || diff.AddedFindings[0] != (FindingRef{"CVE-NEW", "pkg:npm/b@2.0.0"}) ||
		len(diff.RemovedFindings) != 1 || diff.RemovedFindings[0] != (FindingRef{"CVE-OLD", "pkg:npm/b@1.0.0"}) {
		t.Fatalf("finding delta = %+v / %+v", diff.AddedFindings, diff.RemovedFindings)
	}
	if _, err := Compare(base, nil); err == nil {
		t.Fatal("nil head accepted")
	}
	if _, err := Compare(&Record{Manifests: []Manifest{{Dependencies: []Dependency{{ID: "pkg:not a purl"}}}}}, head); err == nil {
		t.Fatal("an unmintable identity was accepted")
	}
}
