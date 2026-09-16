package sdk

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPluginRequestResponseRegistryJSON(t *testing.T) {
	registry := NewPackageRegistry()
	registry.Ensure("pkg:npm/lodash@4.17.15").Vulnerabilities = []Vulnerability{{ID: "GHSA-lodash", Source: "osv"}}

	matchData, err := json.Marshal(MatchRequest{Registry: registry})
	if err != nil {
		t.Fatalf("marshal match request: %v", err)
	}
	var matchReq MatchRequest
	if err := json.Unmarshal(matchData, &matchReq); err != nil {
		t.Fatalf("unmarshal match request: %v", err)
	}
	if matchReq.Registry == nil {
		t.Fatal("match request registry was not decoded")
	}
	if pkg, ok := matchReq.Registry.Get("pkg:npm/lodash@4.17.15"); !ok || len(pkg.Vulnerabilities) != 1 {
		t.Fatalf("match request registry package = %#v, ok=%v", pkg, ok)
	}

	resultData, err := json.Marshal(MatchResult{Registry: registry, MatcherStats: MatcherStats{Name: "test-matcher"}})
	if err != nil {
		t.Fatalf("marshal match result: %v", err)
	}
	var matchResult MatchResult
	if err := json.Unmarshal(resultData, &matchResult); err != nil {
		t.Fatalf("unmarshal match result: %v", err)
	}
	if matchResult.Registry == nil {
		t.Fatal("match result registry was not decoded")
	}
	if pkg, ok := matchResult.Registry.Get("pkg:npm/lodash@4.17.15"); !ok || len(pkg.Vulnerabilities) != 1 {
		t.Fatalf("match result registry package = %#v, ok=%v", pkg, ok)
	}

	before := mustWireDep(t, Coordinates{Name: "before"})
	before.Source = DependencySourceRegistry
	after := mustWireDep(t, Coordinates{Name: "after"})
	after.Source = DependencySourceGit
	auditData, err := json.Marshal(AuditRequest{
		Registry: registry,
		DependencyDetailChanges: []DependencyDetailTransition{{
			Before:        before,
			After:         after,
			ChangedFields: []DependencyDetailField{DependencyDetailSource},
		}},
	})
	if err != nil {
		t.Fatalf("marshal audit request: %v", err)
	}
	if !strings.Contains(string(auditData), `"dependencyDetailChanges"`) ||
		!strings.Contains(string(auditData), `"changedFields"`) ||
		strings.Contains(string(auditData), `"ChangedFields"`) {
		t.Fatalf("audit request transition wire shape = %s", auditData)
	}
	var auditReq AuditRequest
	if err := json.Unmarshal(auditData, &auditReq); err != nil {
		t.Fatalf("unmarshal audit request: %v", err)
	}
	if auditReq.Registry == nil {
		t.Fatal("audit request registry was not decoded")
	}
	if pkg, ok := auditReq.Registry.Get("pkg:npm/lodash@4.17.15"); !ok || len(pkg.Vulnerabilities) != 1 {
		t.Fatalf("audit request registry package = %#v, ok=%v", pkg, ok)
	}
	if len(auditReq.DependencyDetailChanges) != 1 ||
		auditReq.DependencyDetailChanges[0].After.Source != DependencySourceGit {
		t.Fatalf("audit request detail changes = %#v", auditReq.DependencyDetailChanges)
	}
}

func TestProtocolV1AuditRequestDefaultsDependencyDetailChanges(t *testing.T) {
	var request AuditRequest
	if err := json.Unmarshal([]byte(`{"ecosystem":"npm","auditorFilter":{}}`), &request); err != nil {
		t.Fatal(err)
	}
	if request.DependencyDetailChanges != nil {
		t.Fatalf("legacy audit request detail changes = %#v, want nil", request.DependencyDetailChanges)
	}
}

func TestProtocolV1DetectorDescriptorDefaultsNewOptionalCapabilities(t *testing.T) {
	legacy := []byte(`{
		"name":"legacy-detector",
		"supportedEcosystems":["npm"],
		"supportedManagers":["npm"],
		"packageManagerSupport":[{
			"packageManager":"npm",
			"evidencePatterns":["package-lock.json"]
		}]
	}`)
	var descriptor DetectorDescriptor
	if err := json.Unmarshal(legacy, &descriptor); err != nil {
		t.Fatalf("unmarshal protocol-v1 descriptor: %v", err)
	}
	if err := ValidateDetectorDescriptor(&descriptor); err != nil {
		t.Fatalf("validate protocol-v1 descriptor: %v", err)
	}
	if descriptor.PackageManagerSupport[0].MultiModule {
		t.Fatal("legacy descriptor unexpectedly opted into multi-module discovery")
	}
	if descriptor.IgnoredDirectories != nil || descriptor.IgnoredDirectoryMarkers != nil {
		t.Fatalf("legacy optional capabilities should remain absent: %#v", descriptor)
	}
}

// TestPackageUpdatesAreGatedOnTheWire pins the path the registry gate could
// never cover. A matcher or analyzer returns PackageUpdates on its result, and
// the plugin transport serializes those directly — never through
// PackageRegistry — so a gate that lived only at the registry let a
// credential-bearing homepage cross the wire and let already-rejected contacts
// and digests encode as empty "{}" objects.
func TestPackageUpdatesAreGatedOnTheWire(t *testing.T) {
	result := MatchResult{PackageUpdates: []*Package{{
		Coordinates: Coordinates{PURL: "pkg:npm/a@1.0.0"},
		Homepage:    "https://user:pw@evil.test/",
		Description: "bad\x07text",
		Supplier:    &Contact{Kind: ContactKindOrganization},
		Digests: []Digest{
			{Algorithm: "crc32", Value: "zz"},
			{Algorithm: DigestAlgorithmSHA256, Value: "ok"},
		},
	}}}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("encode result: %v", err)
	}
	for _, forbidden := range []string{"user:pw", "\\u0007", `"supplier"`, "{}"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("serialized package updates contain %s: %s", forbidden, encoded)
		}
	}
	if !strings.Contains(string(encoded), `"value":"ok"`) {
		t.Fatalf("the publishable digest was dropped too: %s", encoded)
	}

	// The gate applies on the way in as well.
	var decoded Package
	if err := json.Unmarshal([]byte(`{"purl":"pkg:npm/a@1.0.0","homepage":"https://user:pw@evil.test/"}`), &decoded); err != nil {
		t.Fatalf("decode package: %v", err)
	}
	if decoded.Homepage != "" {
		t.Fatalf("credentials survived the package decoder: %q", decoded.Homepage)
	}

	// Marshaling must not rewrite the record its holder still owns.
	held := &Package{Coordinates: Coordinates{PURL: "pkg:npm/a@1.0.0"}, Homepage: "https://user:pw@evil.test/"}
	if _, err := json.Marshal(held); err != nil {
		t.Fatalf("encode package: %v", err)
	}
	if held.Homepage != "https://user:pw@evil.test/" {
		t.Fatalf("marshaling mutated the caller's record: %q", held.Homepage)
	}
}

// mustWireDep builds a dependency node for a wire fixture, failing the test on
// constructor error.
func mustWireDep(t testing.TB, coords Coordinates) *DependencyNode {
	t.Helper()
	node, err := NewDependencyNode(coords)
	if err != nil {
		t.Fatalf("NewDependencyNode(%+v): %v", coords, err)
	}
	return node
}
