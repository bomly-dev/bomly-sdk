package scan

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func sampleRecord() *Record {
	return &Record{
		Command: "scan",
		Subject: Subject{Kind: plugin.ExecutionTargetGitRepository, RepositoryURL: "https://example.test/acme/app", Ref: "refs/heads/main", CommitSHA: "0123abcdef0123abcdef0123abcdef0123abcdef"},
		Run:     Run{ID: "run-1", StartedAt: time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC), Tool: Tool{Name: "bomly", Version: "1.0.0"}, Options: Options{Enrich: true, Audit: true, FailOn: []string{"high"}}},
		Manifests: []Manifest{
			{Path: "b/package-lock.json", Kind: model.ManifestKindPackageLockJSON, Dependencies: []Dependency{{ID: "pkg:npm/z@1.0.0", PURL: "pkg:npm/z@1.0.0"}}},
			{Path: "a/package-lock.json", Kind: model.ManifestKindPackageLockJSON, Dependencies: []Dependency{
				{ID: "pkg:npm/b@1.0.0", PURL: "pkg:npm/b@1.0.0", DependsOn: []string{"pkg:npm/z@1.0.0", "pkg:npm/a@1.0.0"}},
				{ID: "pkg:npm/a@1.0.0", PURL: "pkg:npm/a@1.0.0", Scopes: []model.Scope{model.ScopeRuntime}},
			}},
		},
		Packages: []*model.Package{
			{Coordinates: model.Coordinates{PURL: "pkg:npm/z@1.0.0", Name: "z"}},
			nil,
			{Coordinates: model.Coordinates{PURL: "pkg:npm/a@1.0.0", Name: "a"}, Vulnerabilities: []model.Vulnerability{{ID: "CVE-1"}}},
		},
		Findings: []model.Finding{
			{ID: "CVE-1", Kind: model.FindingKindVulnerability, PackageRef: "pkg:npm/z@1.0.0", Severity: "high", PolicyStatus: model.FindingPolicyStatusFail},
			{ID: "CVE-1", Kind: model.FindingKindVulnerability, PackageRef: "pkg:npm/a@1.0.0", Severity: "high", PolicyStatus: model.FindingPolicyStatusFail},
		},
		Warnings: []plugin.DetectorWarning{{Type: "package-manager", Message: "b"}, {Type: "package-manager", Message: "a"}},
		Verdict:  VerdictFail,
		Waivers:  []Waiver{{ID: "w2"}, {ID: "w1"}},
	}
}

func TestEncodeIsOrderIndependentAndDoesNotMutate(t *testing.T) {
	forward := sampleRecord()
	before, _ := json.Marshal(forward)
	a, err := Encode(forward)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(forward)
	if !bytes.Equal(before, after) {
		t.Fatal("Encode modified its argument")
	}
	shuffled := sampleRecord()
	shuffled.Manifests[0], shuffled.Manifests[1] = shuffled.Manifests[1], shuffled.Manifests[0]
	shuffled.Packages[0], shuffled.Packages[2] = shuffled.Packages[2], shuffled.Packages[0]
	shuffled.Findings[0], shuffled.Findings[1] = shuffled.Findings[1], shuffled.Findings[0]
	for i := range shuffled.Manifests {
		if shuffled.Manifests[i].Path == "a/package-lock.json" {
			shuffled.Manifests[i].Dependencies[0].DependsOn = []string{"pkg:npm/a@1.0.0", "pkg:npm/z@1.0.0"}
		}
	}
	b, err := Encode(shuffled)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("reordered content encodes differently:\n%s\n%s", a, b)
	}
	// The order is the documented one.
	decoded, err := Decode(a)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Manifests[0].Path != "a/package-lock.json" || decoded.Manifests[0].Dependencies[0].ID != "pkg:npm/a@1.0.0" ||
		decoded.Manifests[0].Dependencies[1].DependsOn[0] != "pkg:npm/a@1.0.0" ||
		len(decoded.Packages) != 2 || decoded.Packages[0].PURL != "pkg:npm/a@1.0.0" ||
		decoded.Findings[0].PackageRef != "pkg:npm/a@1.0.0" || decoded.Warnings[0].Message != "a" || decoded.Waivers[0].ID != "w1" {
		t.Fatalf("not canonical: %+v", decoded)
	}
	if decoded.Digests == nil || !strings.HasPrefix(decoded.Digests.Manifests, "sha256:") || decoded.SchemaVersion != SchemaVersion {
		t.Fatalf("digests or schema missing: %+v", decoded)
	}
}

func TestEncodeDecodeEncodeIsAFixedPoint(t *testing.T) {
	a, err := Encode(sampleRecord())
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(a)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encode(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("not a fixed point:\n%s\n%s", a, b)
	}
	d1, _ := Digest(sampleRecord())
	d2, _ := Digest(decoded)
	if d1 != d2 || !strings.HasPrefix(d1, "sha256:") {
		t.Fatalf("digests differ: %s %s", d1, d2)
	}
	if !bytes.Contains(a, []byte(`"started_at":"2026-09-24T00:00:00Z"`)) || bytes.Contains(a, []byte("completed_at")) {
		t.Fatalf("time fields not omitzero: %s", a)
	}
}

func TestDecodeRefusesAForeignSchemaAndTamperedDigests(t *testing.T) {
	data, _ := Encode(sampleRecord())
	foreign := bytes.Replace(data, []byte(SchemaVersion), []byte("bomly.scan.v2"), 1)
	if _, err := Decode(foreign); !errors.Is(err, ErrSchemaVersion) {
		t.Fatalf("foreign schema: %v", err)
	}
	tampered := bytes.Replace(data, []byte(`"name":"a"`), []byte(`"name":"A"`), 1)
	if _, err := Decode(tampered); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("tampered content: %v", err)
	}
	// A record without digests, and one with unknown keys, still reads.
	if _, err := Decode([]byte(`{"schema_version":"bomly.scan.v1","future":{"x":[1]}}`)); err != nil {
		t.Fatalf("additive keys refused: %v", err)
	}
	if _, err := Decode([]byte(`{"schema_version":"bomly.scan.v1","digests":{"manifests":"sha256:00"}}`)); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("wrong digest accepted: %v", err)
	}
	for _, bad := range []string{`null`, `[]`, `{`, `"x"`} {
		if _, err := Decode([]byte(bad)); err == nil {
			t.Fatalf("%s decoded", bad)
		}
	}
}

func TestDecodeRefusesOverBound(t *testing.T) {
	previous := recordBounds
	t.Cleanup(func() { recordBounds = previous })
	data, _ := Encode(sampleRecord())

	recordBounds.bytes = 8
	if _, err := Decode(data); !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("bytes: %v", err)
	}
	recordBounds = previous
	recordBounds.manifests = 1
	if _, err := Decode(data); !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("manifests: %v", err)
	}
	recordBounds = previous
	recordBounds.dependencies = 1
	if _, err := Decode(data); !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("dependencies: %v", err)
	}
	recordBounds = previous
	recordBounds.packages = 1
	if _, err := Decode(data); !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("packages: %v", err)
	}
	recordBounds = previous
	recordBounds.findings = 1
	if _, err := Decode(data); !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("findings: %v", err)
	}
}

func FuzzDecode(f *testing.F) {
	minimal, _ := Encode(&Record{})
	full, _ := Encode(sampleRecord())
	f.Add(minimal)
	f.Add(full)
	f.Add(bytes.Replace(full, []byte(SchemaVersion), []byte("bomly.scan.v2"), 1))
	f.Add(bytes.Replace(full, []byte(`"name":"a"`), []byte(`"name":"A"`), 1))
	f.Add(full[:len(full)/2])
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"schema_version":"bomly.scan.v1","manifests":[{"dependencies":[{"id":"pkg:npm/a@1","depends_on":["b","a"]}]}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		record, err := Decode(data)
		if err != nil {
			return
		}
		once, err := Encode(record)
		if err != nil {
			t.Fatalf("encode a decoded record: %v", err)
		}
		again, err := Decode(once)
		if err != nil {
			t.Fatalf("decode an encoded record: %v", err)
		}
		twice, err := Encode(again)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(once, twice) {
			t.Fatalf("not a fixed point:\n%s\n%s", once, twice)
		}
	})
}

// The digests are verified by a reader over what it decoded, so they must
// be taken over that form: an open value -- a struct in a package's
// metadata, an integer past 2^53 -- encodes one way from memory and
// another after a round trip, and a digest over the former refused a
// record this package had just written.
func TestEncodeDigestsWhatAReaderDecodes(t *testing.T) {
	type ordered struct {
		B int `json:"b"`
		A int `json:"a"`
	}
	r := sampleRecord()
	r.Packages[0].Metadata = map[string]any{"npm": ordered{B: 1, A: 2}, "n": int64(1<<60 + 1)}
	r.Packages[2].Vulnerabilities[0].DatabaseSpecific = map[string]any{"z": []any{ordered{B: 3, A: 4}}, "a": uint64(1<<63 + 5)}
	data, err := Encode(r)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := Decode(data); err != nil {
		t.Fatalf("Decode refused a record Encode wrote: %v", err)
	}
}

// Scopes are a union across declaration sites and arrive in visiting
// order; two records that agree on the set encode to the same bytes.
func TestEncodeSortsScopes(t *testing.T) {
	a, b := sampleRecord(), sampleRecord()
	a.Manifests[1].Dependencies[1].Scopes = []model.Scope{model.ScopeRuntime, model.ScopeDevelopment, model.ScopeRuntime}
	b.Manifests[1].Dependencies[1].Scopes = []model.Scope{model.ScopeDevelopment, model.ScopeRuntime}
	left, err := Encode(a)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(left, right) {
		t.Fatalf("scope order changed the bytes:\n%s\n%s", left, right)
	}
	if !strings.Contains(string(left), `"scopes":["development","runtime"]`) {
		t.Fatalf("scopes are not sorted and deduplicated: %s", left)
	}
}

// A digest is verified over the section's bytes as written, so a record a
// later minor of the schema wrote -- carrying a key this reader does not
// know -- and a record a tool indented for a reader both verify.
func TestDecodeVerifiesDigestsOverTheBytesAsWritten(t *testing.T) {
	data, err := Encode(sampleRecord())
	if err != nil {
		t.Fatal(err)
	}
	later := bytes.Replace(data, []byte(`"path":"a/package-lock.json"`), []byte(`"path":"a/package-lock.json","from_a_later_minor":{"x":[1,2]}`), 1)
	if bytes.Equal(later, data) {
		t.Fatal("the fixture did not take the extra key")
	}
	var digests struct {
		Digests SectionDigests `json:"digests"`
	}
	if err := json.Unmarshal(later, &digests); err != nil {
		t.Fatal(err)
	}
	// The writer of that key digested its own bytes; stand in for it.
	actual, err := sectionDigestsOf(later)
	if err != nil {
		t.Fatal(err)
	}
	later = bytes.Replace(later, []byte(digests.Digests.Manifests), []byte(actual.Manifests), 1)
	if _, err := Decode(later); err != nil {
		t.Fatalf("a record from a later minor was refused: %v", err)
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, data, "", "  "); err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(indented.Bytes()); err != nil {
		t.Fatalf("an indented record was refused: %v", err)
	}
	// Content that moved is still refused.
	moved := bytes.Replace(data, []byte(`"pkg:npm/z@1.0.0"`), []byte(`"pkg:npm/y@1.0.0"`), 1)
	if _, err := Decode(moved); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("changed content decoded: %v", err)
	}
}

// Findings sharing an ID and a package can still be two findings; the
// bytes must not depend on the order the auditors produced them. Locations
// are a set folded by usage, in whatever order the sites were visited.
func TestEncodeOrdersFindingsAndLocationsTotally(t *testing.T) {
	a, b := sampleRecord(), sampleRecord()
	vuln := model.Finding{ID: "X", PackageRef: "pkg:npm/a@1.0.0", Kind: model.FindingKindVulnerability, VulnerabilityID: "X"}
	policy := model.Finding{ID: "X", PackageRef: "pkg:npm/a@1.0.0", Kind: model.FindingKindPackage, RuleID: "denied"}
	a.Findings = append(a.Findings, vuln, policy)
	b.Findings = append(b.Findings, policy, vuln)
	a.Waivers = append(a.Waivers, Waiver{PackageRef: "p2"}, Waiver{PackageRef: "p1"})
	b.Waivers = append(b.Waivers, Waiver{PackageRef: "p1"}, Waiver{PackageRef: "p2"})
	first := model.PackageLocation{RealPath: "a/package-lock.json", ModuleRoot: "a", Scopes: []model.Scope{model.ScopeRuntime, model.ScopeDevelopment}}
	second := model.PackageLocation{RealPath: "a/package.json", ModuleRoot: "a", Scopes: []model.Scope{model.ScopeDevelopment, model.ScopeRuntime}}
	a.Manifests[1].Dependencies[1].Locations = []model.PackageLocation{second, first, first}
	b.Manifests[1].Dependencies[1].Locations = []model.PackageLocation{first, second}
	left, err := Encode(a)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(left, right) {
		t.Fatalf("input order changed the bytes:\n%s\n%s", left, right)
	}
	if strings.Count(string(left), `"real_path":"a/package-lock.json"`) != 1 || strings.Index(string(left), `"real_path":"a/package-lock.json"`) > strings.Index(string(left), `"real_path":"a/package.json"`) {
		t.Fatalf("locations are not folded and sorted: %s", left)
	}
}

// License claims are a set, on a package and on a dependency alike; the
// order the witnesses arrived in must not reach the bytes.
func TestEncodeOrdersPackageLicenseClaims(t *testing.T) {
	a, b := sampleRecord(), sampleRecord()
	a.Packages[0].Licenses = []model.PackageLicense{{Value: "MIT", Type: model.LicenseTypeDeclared}, {Value: "Apache-2.0", Type: model.LicenseTypeDeclared}}
	b.Packages[0].Licenses = []model.PackageLicense{{Value: "Apache-2.0", Type: model.LicenseTypeDeclared}, {Value: "MIT", Type: model.LicenseTypeDeclared}}
	a.Manifests[1].Dependencies[1].Licenses = []model.PackageLicense{{Value: "MIT"}, {Value: "ISC"}}
	b.Manifests[1].Dependencies[1].Licenses = []model.PackageLicense{{Value: "ISC"}, {Value: "MIT"}}
	left, err := Encode(a)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(left, right) {
		t.Fatalf("license order changed the bytes:\n%s\n%s", left, right)
	}
}
