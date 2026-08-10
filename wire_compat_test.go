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
	} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var decoded map[string]json.RawMessage
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, forbidden := range []string{"acceptPackageUpdates", "packageUpdates", "capabilities", "configSchema"} {
			if _, ok := decoded[forbidden]; ok {
				t.Errorf("%s: zero-valued %q must be omitted from the wire", name, forbidden)
			}
		}
	}
}
