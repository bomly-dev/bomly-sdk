package sdk

import (
	"encoding/json"
	"testing"
)

// These fixtures freeze protocol v1 wire payloads as produced by hosts and
// plugins built before newer optional fields existed. They must decode
// forever: within protocol v1 the wire contract is strictly additive — new
// fields are optional (omitempty) and unknown fields are ignored. Do not
// update a fixture to "fix" a failing test; a failure here means the change
// under review breaks old binaries.

const wireV1MatchRequest = `{
  "projectPath": "/work/project",
  "executionTarget": {},
  "subprojectInfo": {},
  "ecosystem": "javascript",
  "packageManager": "npm",
  "query": {},
  "registry": {"pkg:npm/left-pad@1.3.0": {"purl": "pkg:npm/left-pad@1.3.0", "name": "left-pad", "version": "1.3.0"}},
  "matcherFilter": {}
}`

const wireV1MatchResult = `{
  "registry": {"pkg:npm/left-pad@1.3.0": {"purl": "pkg:npm/left-pad@1.3.0", "name": "left-pad", "version": "1.3.0"}},
  "matcherStats": {"name": "legacy-matcher"}
}`

const wireV1AuditRequest = `{
  "executionTarget": {},
  "subprojectInfo": {},
  "query": {},
  "auditorFilter": {}
}`

const wireV1ReadyResponse = `{"ready": false, "reason": "toolchain missing"}`

const wireV1MatcherDescriptor = `{
  "name": "legacy-matcher",
  "displayName": "Legacy Matcher",
  "supportedEcosystems": ["javascript"]
}`

// wireFutureMatchResult simulates a payload from a NEWER peer that carries
// fields this build does not know. encoding/json must ignore them.
const wireFutureMatchResult = `{
  "registry": null,
  "packageUpdates": [{"purl": "pkg:npm/left-pad@1.3.0", "licenses": [{"id": "MIT"}]}],
  "matcherStats": {"name": "future-matcher"},
  "someFutureField": {"nested": true}
}`

func TestWireV1FixturesDecode(t *testing.T) {
	var matchReq MatchRequest
	if err := json.Unmarshal([]byte(wireV1MatchRequest), &matchReq); err != nil {
		t.Fatalf("v1 MatchRequest no longer decodes: %v", err)
	}
	if matchReq.AcceptPackageUpdates {
		t.Fatal("v1 MatchRequest must default AcceptPackageUpdates to false")
	}
	if matchReq.Registry == nil {
		t.Fatal("v1 MatchRequest registry lost")
	}
	if _, ok := matchReq.Registry.Get("pkg:npm/left-pad@1.3.0"); !ok {
		t.Fatal("v1 MatchRequest registry package lost")
	}

	var matchRes MatchResult
	if err := json.Unmarshal([]byte(wireV1MatchResult), &matchRes); err != nil {
		t.Fatalf("v1 MatchResult no longer decodes: %v", err)
	}
	if matchRes.Registry == nil || matchRes.PackageUpdates != nil {
		t.Fatalf("v1 MatchResult shape drifted: %+v", matchRes)
	}

	var auditReq AuditRequest
	if err := json.Unmarshal([]byte(wireV1AuditRequest), &auditReq); err != nil {
		t.Fatalf("v1 AuditRequest no longer decodes: %v", err)
	}

	var ready ReadyResponse
	if err := json.Unmarshal([]byte(wireV1ReadyResponse), &ready); err != nil {
		t.Fatalf("v1 ReadyResponse no longer decodes: %v", err)
	}
	if ready.Ready || ready.Reason != "toolchain missing" {
		t.Fatalf("v1 ReadyResponse fields drifted: %+v", ready)
	}

	var descriptor MatcherDescriptor
	if err := json.Unmarshal([]byte(wireV1MatcherDescriptor), &descriptor); err != nil {
		t.Fatalf("v1 MatcherDescriptor no longer decodes: %v", err)
	}
	if descriptor.Name != "legacy-matcher" || descriptor.Capabilities != nil || descriptor.ConfigSchema != nil {
		t.Fatalf("v1 MatcherDescriptor fields drifted: %+v", descriptor)
	}
}

func TestWireFuturePayloadIgnoredFields(t *testing.T) {
	var res MatchResult
	if err := json.Unmarshal([]byte(wireFutureMatchResult), &res); err != nil {
		t.Fatalf("future MatchResult must decode on old builds: %v", err)
	}
	if len(res.PackageUpdates) != 1 || res.PackageUpdates[0].PURL != "pkg:npm/left-pad@1.3.0" {
		t.Fatalf("packageUpdates lost: %+v", res)
	}
}

// TestWireV1NewFieldsAreOmitEmpty guards the additive rule: zero-valued new
// fields must vanish from the wire so old peers see byte-shapes they know.
func TestWireV1NewFieldsAreOmitEmpty(t *testing.T) {
	for name, value := range map[string]any{
		"MatchRequest":       &MatchRequest{},
		"MatchResult":        &MatchResult{},
		"AnalyzeRequest":     &AnalyzeRequest{},
		"AnalyzeResult":      &AnalyzeResult{},
		"MatcherDescriptor":  &MatcherDescriptor{Name: "x"},
		"AnalyzerDescriptor": &AnalyzerDescriptor{Name: "x"},
		"DetectorDescriptor": &DetectorDescriptor{Name: "x"},
		"AuditorDescriptor":  &AuditorDescriptor{Name: "x"},
		"DependencyNode":     &DependencyNode{},
		"Package":            &Package{},
		"Graph":              New(),
	} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var decoded map[string]json.RawMessage
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, forbidden := range []string{
			"acceptPackageUpdates", "packageUpdates", "capabilities", "configSchema",
			// Identity-phase additions must vanish when zero-valued.
			"origins", "declaring_manifest_path", "detected_origins",
		} {
			if _, ok := decoded[forbidden]; ok {
				t.Errorf("%s: zero-valued %q must be omitted from the wire", name, forbidden)
			}
		}
	}
}

// --- Typed graph-node wire contract (ADR-0041) ---------------------------
// The first node-level fixtures in this file. The kind discriminator, the
// origins list, and the declaring manifest path are additive; nodes keep
// their flat JSON shape. Decode is strict about identity: a dependency
// payload that cannot mint a well-formed package URL fails the decode.

const wireV1GraphExplicitKinds = `{
  "nodes": [
    {"kind": "manifest", "id": "manifest:package.json"},
    {"kind": "module", "id": "module:package.json#app", "name": "app", "declaring_manifest_path": "package.json"},
    {"kind": "dependency", "id": "pkg:npm/left-pad@1.3.0", "purl": "pkg:npm/left-pad@1.3.0", "name": "left-pad", "version": "1.3.0"}
  ],
  "edges": [
    {"fromId": "manifest:package.json", "toId": "module:package.json#app"},
    {"fromId": "module:package.json#app", "toId": "pkg:npm/left-pad@1.3.0"}
  ]
}`

// wireV1GraphLegacyInferred is a pre-union payload with no kind fields:
// the manifest package type infers manifest, the first-party marker infers
// module, and everything else — including the application-typed component
// without the marker — is a dependency (ADR-0015: application type alone
// is never an ownership signal).
const wireV1GraphLegacyInferred = `{
  "nodes": [
    {"id": "manifest:pkg/package.json", "type": "manifest", "name": "package.json"},
    {"id": "app@1.0.0", "name": "app", "version": "1.0.0", "first_party": true, "locations": [{"real_path": "pkg/package.json"}]},
    {"id": "left-pad@1.3.0", "ecosystem": "npm", "name": "left-pad", "version": "1.3.0"},
    {"id": "imported-app@2.0.0", "type": "application", "ecosystem": "npm", "name": "imported-app", "version": "2.0.0"}
  ],
  "edges": [{"fromId": "app@1.0.0", "toId": "left-pad@1.3.0"}]
}`

// wireV1NodeConflictingKind carries an explicit kind that disagrees with
// the legacy package type: the explicit kind is authoritative.
const wireV1NodeConflictingKind = `{
  "nodes": [{"kind": "module", "id": "x", "type": "manifest", "name": "app", "declaring_manifest_path": "pkg/package.json"}]
}`

const wireV1NodeUnknownKind = `{
  "nodes": [{"kind": "container", "id": "x", "name": "y"}]
}`

// wireV1NodeDualOrigins carries both the legacy singular origin and the
// additive origins list, overlapping on one entry: decode unions and
// deduplicates by normalized value.
const wireV1NodeDualOrigins = `{
  "nodes": [{
    "id": "pkg:npm/left-pad@1.3.0", "purl": "pkg:npm/left-pad@1.3.0", "name": "left-pad", "version": "1.3.0",
    "origin": {"artifact_url": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
    "origins": [
      {"artifact_url": "https://REGISTRY.NPMJS.ORG/left-pad/-/left-pad-1.3.0.tgz"},
      {"repository": "https://github.com/left-pad/left-pad", "revision": "v1.3.0"}
    ]
  }]
}`

// wireV1GraphDuplicateFold holds two wire records minting one canonical
// identity: decode folds them — scopes, locations, and origins union, the
// eligibility any-witness rule keeps the registry-eligible source — and
// the edges follow the fold, with the resulting self-edge dropped.
const wireV1GraphDuplicateFold = `{
  "nodes": [
    {"id": "a", "ecosystem": "npm", "name": "left-pad", "version": "1.3.0", "source": "git", "scopes": ["development"], "locations": [{"real_path": "a/package-lock.json"}]},
    {"id": "b", "ecosystem": "npm", "name": "Left-Pad", "version": "1.3.0", "source": "registry", "scopes": ["runtime"], "locations": [{"real_path": "b/package-lock.json"}], "origins": [{"repository": "https://github.com/left-pad/left-pad"}]},
    {"id": "root", "first_party": true, "name": "app", "locations": [{"real_path": "package.json"}]}
  ],
  "edges": [
    {"fromId": "root", "toId": "a"},
    {"fromId": "root", "toId": "b"},
    {"fromId": "a", "toId": "b"}
  ]
}`

// wireV1DependencyInvalidIdentity cannot mint a well-formed package URL
// (no name, no purl): the strict ruling makes this a decode error — "only
// valid PURLs, no exceptions" applies to the wire too.
const wireV1DependencyInvalidIdentity = `{
  "nodes": [{"id": "legacy-opaque", "version": "1.0.0"}]
}`

// wireV1DependencyProfileInvalid carries a syntactically well-formed purl
// that violates its type's specification profile (maven requires the group
// ID namespace): the constructor gate applies at decode.
const wireV1DependencyProfileInvalid = `{
  "nodes": [{"id": "pkg:maven/commons-text@1.10.0", "purl": "pkg:maven/commons-text@1.10.0", "name": "commons-text", "version": "1.10.0"}]
}`

func TestWireV1TypedNodeKinds(t *testing.T) {
	var explicit Graph
	if err := json.Unmarshal([]byte(wireV1GraphExplicitKinds), &explicit); err != nil {
		t.Fatalf("explicit-kind graph no longer decodes: %v", err)
	}
	if explicit.Size() != 3 {
		t.Fatalf("explicit graph size = %d", explicit.Size())
	}
	if _, ok := explicit.Node("manifest:package.json"); !ok {
		t.Fatal("manifest node lost")
	}
	if node, _ := explicit.Node("module:package.json#app"); node == nil || node.Kind() != NodeKindModule {
		t.Fatalf("module node = %#v", node)
	}
	if dep, ok := explicit.DependencyNode("pkg:npm/left-pad@1.3.0"); !ok || dep.Kind() != NodeKindDependency {
		t.Fatal("dependency node lost")
	}

	var legacy Graph
	if err := json.Unmarshal([]byte(wireV1GraphLegacyInferred), &legacy); err != nil {
		t.Fatalf("legacy payload no longer decodes: %v", err)
	}
	kinds := map[NodeKind]int{}
	legacy.WalkNodes(func(node GraphNode) bool {
		kinds[node.Kind()]++
		return true
	})
	if kinds[NodeKindManifest] != 1 || kinds[NodeKindModule] != 1 || kinds[NodeKindDependency] != 2 {
		t.Fatalf("legacy kind inference = %v", kinds)
	}
	if imported, ok := legacy.DependencyNode("pkg:npm/imported-app@2.0.0"); !ok || imported == nil {
		t.Fatalf("application-typed import must stay a dependency node; nodes: %v", legacy.PrettyString())
	}
	// Legacy name@version IDs re-identify to canonical package URLs, and
	// edges follow the mapping.
	folded, ok := legacy.DependencyNode("pkg:npm/left-pad@1.3.0")
	if !ok {
		t.Fatalf("legacy left-pad ID did not re-identify; graph: %v", legacy.PrettyString())
	}
	parents, err := legacy.Dependents(folded.NodeID())
	if err != nil || len(parents) != 1 || parents[0].Kind() != NodeKindModule {
		t.Fatalf("edge did not follow the re-identified node: %v, %v", parents, err)
	}

	var conflicting Graph
	if err := json.Unmarshal([]byte(wireV1NodeConflictingKind), &conflicting); err != nil {
		t.Fatalf("conflicting-kind payload no longer decodes: %v", err)
	}
	nodes := conflicting.Nodes()
	if len(nodes) != 1 || nodes[0].Kind() != NodeKindModule {
		t.Fatalf("explicit kind must win over the legacy type: %#v", nodes)
	}

	var unknown Graph
	if err := json.Unmarshal([]byte(wireV1NodeUnknownKind), &unknown); err == nil {
		t.Fatal("unknown kind must be a decode error, never a guess")
	}
}

func TestWireV1DualOriginFieldsUnion(t *testing.T) {
	var graph Graph
	if err := json.Unmarshal([]byte(wireV1NodeDualOrigins), &graph); err != nil {
		t.Fatalf("dual-origin payload no longer decodes: %v", err)
	}
	dep, ok := graph.DependencyNode("pkg:npm/left-pad@1.3.0")
	if !ok {
		t.Fatal("dependency lost")
	}
	if len(dep.Origins) != 2 {
		t.Fatalf("origins = %+v, want the deduplicated union of both fields", dep.Origins)
	}
}

func TestWireV1DuplicateIdentityFolds(t *testing.T) {
	var graph Graph
	if err := json.Unmarshal([]byte(wireV1GraphDuplicateFold), &graph); err != nil {
		t.Fatalf("duplicate-identity payload no longer decodes: %v", err)
	}
	if graph.Size() != 2 {
		t.Fatalf("size = %d, want the duplicates folded beside the module root", graph.Size())
	}
	dep, ok := graph.DependencyNode("pkg:npm/left-pad@1.3.0")
	if !ok {
		t.Fatalf("folded node missing; graph: %v", graph.PrettyString())
	}
	if !dep.HasScope(ScopeRuntime) || !dep.HasScope(ScopeDevelopment) {
		t.Fatalf("fold lost scopes: %v", dep.Scopes)
	}
	if len(dep.Locations) != 2 {
		t.Fatalf("fold lost locations: %+v", dep.Locations)
	}
	if len(dep.Origins) != 1 {
		t.Fatalf("fold lost origins: %+v", dep.Origins)
	}
	// Eligibility folds toward eligible: the registry witness's source wins.
	if !dep.RegistryMatchEligible() {
		t.Fatalf("any-witness eligibility lost: source = %q", dep.Source)
	}
	// The a->b edge became a self-edge after the fold and was dropped;
	// the root keeps exactly one edge to the folded node.
	children, err := graph.DirectDependencies(graph.ModuleNodes()[0].NodeID())
	if err != nil || len(children) != 1 {
		t.Fatalf("edges after fold: %v, %v", children, err)
	}
}

func TestWireV1StrictDependencyIdentity(t *testing.T) {
	var invalid Graph
	if err := json.Unmarshal([]byte(wireV1DependencyInvalidIdentity), &invalid); err == nil {
		t.Fatal("a dependency payload with no derivable package URL must fail decode")
	}
	var profile Graph
	if err := json.Unmarshal([]byte(wireV1DependencyProfileInvalid), &profile); err == nil {
		t.Fatal("a profile-invalid package URL must fail decode")
	}
	// The open vocabulary: a custom purl type is first-class and decodes.
	var custom Graph
	if err := json.Unmarshal([]byte(`{"nodes":[{"id":"pkg:pokemon/pikachu@25","purl":"pkg:pokemon/pikachu@25","name":"pikachu","version":"25"}]}`), &custom); err != nil {
		t.Fatalf("custom purl type must decode: %v", err)
	}
}
