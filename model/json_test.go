package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGraphJSONRoundTrip(t *testing.T) {
	graph := New()
	app := mustDep(t, Coordinates{Name: "app", Version: "1.0.0"})
	dep := mustDep(t, Coordinates{Name: "dep", Version: "2.0.0"})
	if err := graph.AddNode(app); err != nil {
		t.Fatalf("AddNode(app): %v", err)
	}
	if err := graph.AddNode(dep); err != nil {
		t.Fatalf("AddNode(dep): %v", err)
	}
	if err := graph.AddEdge(app.NodeID(), dep.NodeID()); err != nil {
		t.Fatalf("AddEdge(): %v", err)
	}

	data, err := json.Marshal(graph)
	if err != nil {
		t.Fatalf("Marshal(): %v", err)
	}

	var decoded Graph
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal(): %v", err)
	}
	if decoded.Size() != 2 {
		t.Fatalf("decoded graph size = %d, want 2", decoded.Size())
	}
	deps, err := decoded.DirectDependencies(app.NodeID())
	if err != nil {
		t.Fatalf("DirectDependencies(): %v", err)
	}
	if len(deps) != 1 || deps[0].NodeID() != dep.NodeID() {
		t.Fatalf("decoded dependencies = %#v, want %q", deps, dep.NodeID())
	}
}

func TestFindingSuppressedPolicyStatusAndRuleIDJSONRoundTrip(t *testing.T) {
	input := Finding{ID: "finding", Kind: FindingKindPackage, RuleID: "denied-package", PolicyStatus: FindingPolicyStatusSuppressed}
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var output Finding
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatal(err)
	}
	if output.RuleID != input.RuleID || output.PolicyStatus != FindingPolicyStatusSuppressed {
		t.Fatalf("finding round trip = %#v", output)
	}
}

func TestFindingAcceptsProtocolV1LegacyPolicyStatusField(t *testing.T) {
	var finding Finding
	if err := json.Unmarshal([]byte(`{"id":"finding","disposition":"warn"}`), &finding); err != nil {
		t.Fatal(err)
	}
	if finding.PolicyStatus != FindingPolicyStatusWarn {
		t.Fatalf("legacy policy status = %q, want warn", finding.PolicyStatus)
	}
	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"disposition"`) || !strings.Contains(string(data), `"policy_status":"warn"`) {
		t.Fatalf("current finding JSON = %s", data)
	}
}

func TestPackageRegistryJSONRoundTrip(t *testing.T) {
	registry := NewPackageRegistry()
	pkg := registry.Ensure("pkg:npm/react@18.2.0")
	pkg.Name = "react"
	pkg.Version = "18.2.0"
	pkg.Licenses = []PackageLicense{{SPDXExpression: "MIT"}}
	pkg.Vulnerabilities = []Vulnerability{{ID: "GHSA-1", Source: "osv", ParsedSeverity: SeverityHigh}}

	data, err := json.Marshal(registry)
	if err != nil {
		t.Fatalf("Marshal(): %v", err)
	}

	var decoded PackageRegistry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal(): %v", err)
	}
	decodedPkg, ok := decoded.Get("pkg:npm/react@18.2.0")
	if !ok {
		t.Fatalf("decoded registry missing package: %s", data)
	}
	if decodedPkg.Name != "react" || decodedPkg.Version != "18.2.0" {
		t.Fatalf("decoded package identity = %#v", decodedPkg)
	}
	if len(decodedPkg.Licenses) != 1 || decodedPkg.Licenses[0].SPDXExpression != "MIT" {
		t.Fatalf("decoded licenses = %#v", decodedPkg.Licenses)
	}
	if len(decodedPkg.Vulnerabilities) != 1 || decodedPkg.Vulnerabilities[0].ID != "GHSA-1" {
		t.Fatalf("decoded vulnerabilities = %#v", decodedPkg.Vulnerabilities)
	}
}

func TestDependencyNodeWireCarriesComponentAssertions(t *testing.T) {
	graph := New()
	node := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "react", Version: "18.2.0"})
	node.Description = "A JavaScript library."
	node.Homepage = "https://react.test/docs?v=18"
	node.Supplier = &Contact{Kind: ContactKindOrganization, Name: "Meta"}
	node.Originator = &Contact{Kind: ContactKindPerson, Name: "Jane Doe"}
	node.Licenses = []PackageLicense{{Value: "MIT", SPDXExpression: "MIT", Type: LicenseTypeDeclared}}
	if err := graph.AddNode(node); err != nil {
		t.Fatalf("add node: %v", err)
	}

	encoded, err := json.Marshal(graph)
	if err != nil {
		t.Fatalf("encode graph: %v", err)
	}
	var decoded Graph
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("decode graph: %v", err)
	}
	round := decoded.DependencyNodes()
	if len(round) != 1 {
		t.Fatalf("decoded %d dependency nodes, want 1", len(round))
	}
	got := round[0]
	if got.Description != node.Description {
		t.Fatalf("description did not survive the wire: %q", got.Description)
	}
	if got.Homepage != node.Homepage {
		t.Fatalf("homepage did not survive the wire: %q", got.Homepage)
	}
	if got.Supplier == nil || got.Supplier.Name != "Meta" {
		t.Fatalf("supplier did not survive the wire: %+v", got.Supplier)
	}
	if got.Originator == nil || got.Originator.Name != "Jane Doe" {
		t.Fatalf("originator did not survive the wire: %+v", got.Originator)
	}
	if len(got.Licenses) != 1 || got.Licenses[0].Type != LicenseTypeDeclared {
		t.Fatalf("licenses did not survive the wire: %+v", got.Licenses)
	}
}

// TestDependencyNodeWireGatesArrivingAssertions pins that the decoder holds a
// payload to the same rules the encoder does. A plugin is an untrusted
// producer, so a homepage carrying credentials must not become a stored value
// that later code trusts because "it came from the wire".
func TestDependencyNodeWireGatesArrivingAssertions(t *testing.T) {
	payload := `{"nodes":[{"kind":"dependency","id":"pkg:npm/react@18.2.0","purl":"pkg:npm/react@18.2.0",` +
		`"homepage":"https://user:pw@react.test/","description":"bad\u0007text",` +
		`"supplier":{"kind":"organization","name":"Acme\nInc"}}]}`
	var decoded Graph
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("decode graph: %v", err)
	}
	nodes := decoded.DependencyNodes()
	if len(nodes) != 1 {
		t.Fatalf("decoded %d dependency nodes, want 1", len(nodes))
	}
	got := nodes[0]
	if got.Homepage != "" {
		t.Fatalf("credentials survived the decoder: %q", got.Homepage)
	}
	if got.Description != "badtext" {
		t.Fatalf("description = %q, want the control character dropped", got.Description)
	}
	if got.Supplier != nil {
		t.Fatalf("an unpublishable supplier survived the decoder: %+v", got.Supplier)
	}
}

// TestRejectedOptionalAssertionsLeaveNoEmptyWireObjects pins the two shapes
// that omitempty cannot suppress on its own: a non-nil pointer to a rejected
// value, and a rejected element inside a slice. Both would publish an empty
// object where the assertion was supposed to have been dropped.
func TestRejectedOptionalAssertionsLeaveNoEmptyWireObjects(t *testing.T) {
	payload := `{"nodes":[{"kind":"dependency","id":"pkg:npm/a@1.0.0","purl":"pkg:npm/a@1.0.0",` +
		`"supplier":{"kind":"organization"},"originator":{},` +
		`"digests":[{"algorithm":"crc32","value":"zz"},{"algorithm":"sha256","value":"abc"}]}]}`
	var decoded Graph
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("decode graph: %v", err)
	}
	node := decoded.DependencyNodes()[0]
	if node.Supplier != nil || node.Originator != nil {
		t.Fatalf("a rejected contact survived as a pointer: supplier=%+v originator=%+v", node.Supplier, node.Originator)
	}
	if len(node.Digests) != 1 || node.Digests[0].Algorithm != DigestAlgorithmSHA256 {
		t.Fatalf("digests = %+v, want only the publishable one", node.Digests)
	}

	encoded, err := json.Marshal(&decoded)
	if err != nil {
		t.Fatalf("encode graph: %v", err)
	}
	for _, forbidden := range []string{`"supplier":{}`, `"originator":{}`, `{},`, `[{}`} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("encoded graph contains %s: %s", forbidden, encoded)
		}
	}
}
