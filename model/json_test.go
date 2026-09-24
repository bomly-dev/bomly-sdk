package model

import (
	"encoding/json"
	"errors"
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

// TestCopyrightWireIsGatedBothWays pins the codec: a plugin is an untrusted
// producer, and a node built in process never passed a decoder, so the gate
// runs on the way in and on the way out.
func TestCopyrightWireIsGatedBothWays(t *testing.T) {
	payload := `{"nodes":[{"kind":"dependency","id":"pkg:npm/react@18.2.0","purl":"pkg:npm/react@18.2.0",` +
		`"copyright":"Copyright\u0007 Meta\nAll rights reserved"}]}`
	var decoded Graph
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("decode graph: %v", err)
	}
	if got := decoded.DependencyNodes()[0].Copyright; got != "Copyright Meta\nAll rights reserved" {
		t.Fatalf("decoded copyright = %q, want the control character dropped and the line break kept", got)
	}

	graph := New()
	node := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "react", Version: "18.2.0"})
	node.Copyright = strings.Repeat("c", maxCopyrightLength+1)
	if err := graph.AddNode(node); err != nil {
		t.Fatalf("add node: %v", err)
	}
	encoded, err := json.Marshal(graph)
	if err != nil {
		t.Fatalf("encode graph: %v", err)
	}
	if strings.Contains(string(encoded), `"copyright"`) {
		t.Fatalf("an over-long copyright reached the wire: %d bytes encoded", len(encoded))
	}
}

// TestGraphMarshalIsInsertionOrderIndependent pins that the encoding is a
// function of content alone: the same nodes and edges added in another
// order, or removed and added back, marshal to identical bytes.
func TestGraphMarshalIsInsertionOrderIndependent(t *testing.T) {
	coords := []Coordinates{
		{Ecosystem: EcosystemNPM, Name: "a", Version: "1.0.0"},
		{Ecosystem: EcosystemNPM, Name: "b", Version: "1.0.0"},
		{Ecosystem: EcosystemNPM, Name: "c", Version: "1.0.0"},
	}
	type edge struct{ from, to int }
	edges := []edge{{0, 2}, {0, 1}, {1, 2}}

	build := func(nodeOrder []int, edgeOrder []int) (*Graph, []string) {
		graph := New()
		ids := make([]string, len(coords))
		for _, i := range nodeOrder {
			node := mustDep(t, coords[i])
			ids[i] = node.NodeID()
			if err := graph.AddNode(node); err != nil {
				t.Fatalf("AddNode(%d): %v", i, err)
			}
		}
		for _, e := range edgeOrder {
			if err := graph.AddEdge(ids[edges[e].from], ids[edges[e].to]); err != nil {
				t.Fatalf("AddEdge(%d): %v", e, err)
			}
		}
		return graph, ids
	}
	encode := func(graph *Graph) string {
		data, err := json.Marshal(graph)
		if err != nil {
			t.Fatalf("Marshal(): %v", err)
		}
		return string(data)
	}

	forward, ids := build([]int{0, 1, 2}, []int{0, 1, 2})
	reversed, _ := build([]int{2, 1, 0}, []int{2, 1, 0})
	if got, want := encode(reversed), encode(forward); got != want {
		t.Fatalf("reversed insertion encodes differently:\n got %s\nwant %s", got, want)
	}

	// Removing a node frees its slot; adding it back reuses the slot, which
	// is exactly the history the encoding must not reflect.
	reinserted, _ := build([]int{0, 1, 2}, []int{0, 1, 2})
	if !reinserted.RemoveNode(ids[1]) {
		t.Fatal("RemoveNode(b) = false")
	}
	if err := reinserted.AddNode(mustDep(t, coords[1])); err != nil {
		t.Fatalf("re-add b: %v", err)
	}
	for _, e := range []edge{{0, 1}, {1, 2}} {
		if err := reinserted.AddEdge(ids[e.from], ids[e.to]); err != nil {
			t.Fatalf("re-add edge: %v", err)
		}
	}
	if got, want := encode(reinserted), encode(forward); got != want {
		t.Fatalf("remove and re-add encodes differently:\n got %s\nwant %s", got, want)
	}

	// The order is the documented one: nodes by ID, edges by (fromId, toId).
	var decoded struct {
		Nodes []struct {
			ID string `json:"id"`
		} `json:"nodes"`
		Edges []DependencyEdge `json:"edges"`
	}
	if err := json.Unmarshal([]byte(encode(forward)), &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for i := 1; i < len(decoded.Nodes); i++ {
		if decoded.Nodes[i-1].ID >= decoded.Nodes[i].ID {
			t.Fatalf("nodes not in ID order: %q before %q", decoded.Nodes[i-1].ID, decoded.Nodes[i].ID)
		}
	}
	for i := 1; i < len(decoded.Edges); i++ {
		prev, next := decoded.Edges[i-1], decoded.Edges[i]
		if prev.FromID > next.FromID || (prev.FromID == next.FromID && prev.ToID >= next.ToID) {
			t.Fatalf("edges not in (fromId, toId) order: %v before %v", prev, next)
		}
	}
}

// withGraphBounds shrinks the decode bounds for one test so a refusal can be
// exercised without building a payload the size of the real bound.
func withGraphBounds(t *testing.T, bounds graphBounds) {
	t.Helper()
	previous := graphDecodeBounds
	graphDecodeBounds = bounds
	t.Cleanup(func() { graphDecodeBounds = previous })
}

func withRegistryBounds(t *testing.T, bounds registryBounds) {
	t.Helper()
	previous := registryDecodeBounds
	registryDecodeBounds = bounds
	t.Cleanup(func() { registryDecodeBounds = previous })
}

func TestGraphUnmarshalRefusesRepeatedSectionKeys(t *testing.T) {
	for _, payload := range []string{
		`{"nodes":[],"nodes":[]}`,
		`{"edges":[],"nodes":[],"edges":[]}`,
	} {
		var graph Graph
		err := json.Unmarshal([]byte(payload), &graph)
		if err == nil || !strings.Contains(err.Error(), "key repeated") {
			t.Fatalf("Unmarshal(%s) error = %v, want a repeated-key refusal", payload, err)
		}
	}
}

func TestGraphUnmarshalAcceptsEdgesBeforeNodesAndUnknownKeys(t *testing.T) {
	payload := `{"future":{"nested":[1,2]},"edges":[{"fromId":"a","toId":"b"}],"nodes":[{"id":"a","name":"a","version":"1.0.0"},{"id":"b","name":"b","version":"1.0.0"}],"nodes_count":2}`
	var graph Graph
	if err := json.Unmarshal([]byte(payload), &graph); err != nil {
		t.Fatalf("Unmarshal(): %v", err)
	}
	if graph.Size() != 2 {
		t.Fatalf("size = %d, want 2", graph.Size())
	}
	// Wire IDs are re-minted on decode, so count the edge rather than
	// looking it up by its wire name.
	edges := 0
	graph.WalkTypedEdges(func(_, _ GraphNode, _ EdgeKind) bool {
		edges++
		return true
	})
	if edges != 1 {
		t.Fatalf("edges = %d, want 1", edges)
	}
}

func TestGraphUnmarshalRefusesMoreNodesThanTheBound(t *testing.T) {
	withGraphBounds(t, graphBounds{bytes: MaxPayloadBytes, nodes: 2, edges: MaxGraphEdges})
	payload := `{"nodes":[{"id":"a","name":"a","version":"1"},{"id":"b","name":"b","version":"1"},{"id":"c","name":"c","version":"1"}]}`
	var graph Graph
	err := json.Unmarshal([]byte(payload), &graph)
	if !errors.Is(err, ErrPayloadTooLarge) || !strings.Contains(err.Error(), "graph nodes") {
		t.Fatalf("error = %v, want ErrPayloadTooLarge for graph nodes", err)
	}
	// The bound is a bound, not a truncation: nothing of the payload survives.
	if graph.Size() != 0 {
		t.Fatalf("a refused payload left %d nodes behind", graph.Size())
	}
}

func TestGraphUnmarshalRefusesMoreEdgesThanTheBound(t *testing.T) {
	withGraphBounds(t, graphBounds{bytes: MaxPayloadBytes, nodes: MaxGraphNodes, edges: 1})
	payload := `{"nodes":[{"id":"a","name":"a","version":"1"},{"id":"b","name":"b","version":"1"},{"id":"c","name":"c","version":"1"}],"edges":[{"fromId":"a","toId":"b"},{"fromId":"a","toId":"c"}]}`
	var graph Graph
	err := json.Unmarshal([]byte(payload), &graph)
	if !errors.Is(err, ErrPayloadTooLarge) || !strings.Contains(err.Error(), "graph edges") {
		t.Fatalf("error = %v, want ErrPayloadTooLarge for graph edges", err)
	}
}

func TestGraphUnmarshalRefusesOverBoundBytes(t *testing.T) {
	withGraphBounds(t, graphBounds{bytes: 16, nodes: MaxGraphNodes, edges: MaxGraphEdges})
	var graph Graph
	err := json.Unmarshal([]byte(`{"nodes":[],"edges":[]}`), &graph)
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("error = %v, want ErrPayloadTooLarge", err)
	}
	if err := json.Unmarshal([]byte(`{"nodes":[]}`), &graph); err != nil {
		t.Fatalf("a payload within the bound was refused: %v", err)
	}
}

func TestGraphUnmarshalRefusesTrailingData(t *testing.T) {
	var graph Graph
	if err := json.Unmarshal([]byte(`{"nodes":[]} {"nodes":[]}`), &graph); err == nil {
		t.Fatal("trailing data was accepted")
	}
}

func TestPackageRegistryUnmarshalRefusesOverBound(t *testing.T) {
	withRegistryBounds(t, registryBounds{bytes: MaxPayloadBytes, packages: 1})
	var registry PackageRegistry
	err := json.Unmarshal([]byte(`{"pkg:npm/a@1.0.0":{"name":"a"},"pkg:npm/b@1.0.0":{"name":"b"}}`), &registry)
	if !errors.Is(err, ErrPayloadTooLarge) || !strings.Contains(err.Error(), "package registry") {
		t.Fatalf("error = %v, want ErrPayloadTooLarge for the registry", err)
	}
	// A repeated key is one package, not two, so it fits under the bound.
	if err := json.Unmarshal([]byte(`{"pkg:npm/a@1.0.0":{"name":"a"},"pkg:npm/a@1.0.0":{"name":"a","matched":true}}`), &registry); err != nil {
		t.Fatalf("repeated key refused: %v", err)
	}
	pkg, ok := registry.Get("pkg:npm/a@1.0.0")
	if !ok || !pkg.Matched {
		t.Fatalf("repeated key did not keep the last member: %+v", pkg)
	}

	withRegistryBounds(t, registryBounds{bytes: 8, packages: MaxRegistryPackages})
	if err := json.Unmarshal([]byte(`{"pkg:npm/a@1.0.0":{}}`), &registry); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("error = %v, want ErrPayloadTooLarge for bytes", err)
	}
}

// TestDecodeBoundsAdmitTheLargestKnownWorkspace documents what the bounds
// are sized against: the largest real dependency graphs are a few tens of
// thousands of nodes, and the bounds leave several times that.
func TestDecodeBoundsAdmitTheLargestKnownWorkspace(t *testing.T) {
	const largestKnownNodes = 50_000
	if MaxGraphNodes < 5*largestKnownNodes {
		t.Fatalf("MaxGraphNodes = %d leaves under 5x the largest known workspace", MaxGraphNodes)
	}
	if MaxGraphEdges < 8*MaxGraphNodes {
		t.Fatalf("MaxGraphEdges = %d is under 8 per node", MaxGraphEdges)
	}
	if MaxRegistryPackages != MaxGraphNodes {
		t.Fatalf("MaxRegistryPackages = %d, want MaxGraphNodes", MaxRegistryPackages)
	}
}
