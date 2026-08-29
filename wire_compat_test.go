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

// wireV1Dependency freezes a Dependency node exactly as a pre-identity-phase
// (v0.5.x) peer serialized it: a StableID-shaped id, raw evidence, origin,
// and metadata. The identity phase adds no wire fields — occurrence facets
// and content addresses are in-process, derived state — so this payload must
// decode forever and re-marshal to the same key set.
const wireV1Dependency = `{
  "purl": "pkg:npm/left-pad@1.3.0",
  "ecosystem": "javascript",
  "package_manager": "npm",
  "type": "library",
  "name": "left-pad",
  "version": "1.3.0",
  "id": "left-pad@1.3.0",
  "relationship": "direct",
  "scopes": ["runtime"],
  "locations": [{"real_path": "package-lock.json", "access_path": "package-lock.json", "position": {"file": "package-lock.json", "line": 12}}],
  "found_by": "node",
  "resolved_url": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
  "origin": {"artifact_url": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
  "metadata": {"bomly.normalization.applied": ["name"]},
  "matched": true,
  "package_ref": "pkg:npm/left-pad@1.3.0"
}`

// wireV1Graph freezes a two-node, one-edge detector graph as serialized by a
// v0.5.x peer, including a node whose id is a bare StableID shape.
const wireV1Graph = `{
  "nodes": [
    {"id": "app@1.0.0", "name": "app", "version": "1.0.0", "first_party": true},
    {"id": "left-pad@1.3.0", "purl": "pkg:npm/left-pad@1.3.0", "name": "left-pad", "version": "1.3.0"}
  ],
  "edges": [{"fromId": "app@1.0.0", "toId": "left-pad@1.3.0"}]
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

	var dep Dependency
	if err := json.Unmarshal([]byte(wireV1Dependency), &dep); err != nil {
		t.Fatalf("v1 Dependency no longer decodes: %v", err)
	}
	if dep.ID != "left-pad@1.3.0" || dep.PURL != "pkg:npm/left-pad@1.3.0" || len(dep.Scopes) != 1 || len(dep.Locations) != 1 {
		t.Fatalf("v1 Dependency shape drifted: %+v", dep)
	}
	if dep.Origin == nil || dep.Origin.ArtifactURL == "" {
		t.Fatal("v1 Dependency origin lost")
	}
	if dep.OccurrenceFacet() != "" {
		t.Fatal("a decoded v1 Dependency must carry no occurrence facet — the facet is in-process state, never wire data")
	}
	// The identity phase must not add wire surface: re-marshaling a decoded
	// v1 node emits exactly the keys the fixture carried.
	assertSameJSONKeys(t, "Dependency", []byte(wireV1Dependency), &dep)

	var graph Graph
	if err := json.Unmarshal([]byte(wireV1Graph), &graph); err != nil {
		t.Fatalf("v1 Graph no longer decodes: %v", err)
	}
	if graph.Size() != 2 {
		t.Fatalf("v1 Graph node count = %d, want 2", graph.Size())
	}
	if _, ok := graph.Node("app@1.0.0"); !ok {
		t.Fatal("v1 Graph StableID-shaped node lost")
	}
}

// assertSameJSONKeys re-marshals value and requires the emitted top-level
// key set to equal the fixture's — no new keys may appear on the wire.
func assertSameJSONKeys(t *testing.T, name string, fixture []byte, value any) {
	t.Helper()
	remarshaled, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("%s: re-marshal: %v", name, err)
	}
	var want, got map[string]json.RawMessage
	if err := json.Unmarshal(fixture, &want); err != nil {
		t.Fatalf("%s: fixture: %v", name, err)
	}
	if err := json.Unmarshal(remarshaled, &got); err != nil {
		t.Fatalf("%s: re-marshaled: %v", name, err)
	}
	for key := range got {
		if _, ok := want[key]; !ok {
			t.Errorf("%s: re-marshal emitted new wire key %q", name, key)
		}
	}
	for key := range want {
		if _, ok := got[key]; !ok {
			t.Errorf("%s: re-marshal dropped wire key %q", name, key)
		}
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
		"Dependency":         &Dependency{ID: "x"},
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
			// Identity-phase state is in-process, never wire data; these
			// names failing here means someone promoted it without the
			// coordinated additive-field review.
			"occurrence", "occurrence_facet", "content_address",
		} {
			if _, ok := decoded[forbidden]; ok {
				t.Errorf("%s: zero-valued %q must be omitted from the wire", name, forbidden)
			}
		}
	}
}
