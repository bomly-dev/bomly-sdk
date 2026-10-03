package scan_test

import (
	"fmt"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/scan"
)

// A record is built from what a pipeline holds, encoded to canonical bytes,
// and read back.
func ExampleFromGraphEntries() {
	g := model.New()
	react, _ := model.NewDependencyNodeFromPURL("pkg:npm/react@18.2.0")
	_ = g.AddNode(react)
	registry := model.NewPackageRegistry()
	registry.Ensure(react.NodeID()).Vulnerabilities = []model.Vulnerability{{ID: "CVE-2024-0001"}}
	findings := []model.Finding{{ID: "CVE-2024-0001", Kind: model.FindingKindVulnerability, PackageRef: react.NodeID(), Severity: "high", PolicyStatus: model.FindingPolicyStatusFail}}

	record := scan.FromGraphEntries([]model.GraphEntry{{Graph: g, Manifest: model.ManifestMetadata{Path: "package-lock.json"}}}, registry, findings)
	record.Verdict = scan.VerdictOf(findings)

	data, err := scan.Encode(record)
	if err != nil {
		panic(err)
	}
	decoded, err := scan.Decode(data)
	if err != nil {
		panic(err)
	}
	fmt.Println(decoded.SchemaVersion, len(decoded.Manifests[0].Dependencies), len(decoded.Packages), decoded.Verdict)
	// Output:
	// bomly.scan.v1 1 1 fail
}
