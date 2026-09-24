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
