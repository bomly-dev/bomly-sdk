package sdk

import (
	"encoding/json"
	"strings"
	"testing"
)

// A digest that does not say what it covers means the published artifact, so
// existing producers keep their meaning without changing anything.
func TestDigestSubjectDefaultsToArtifact(t *testing.T) {
	digest := Digest{Algorithm: DigestAlgorithmSHA256, Value: "abc123"}
	if digest.Subject != DigestSubjectArtifact {
		t.Fatalf("subject = %q, want the artifact default", digest.Subject)
	}

	raw, err := json.Marshal(digest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "subject") {
		t.Fatalf("the default subject must not be serialized: %s", raw)
	}
}

// A Go module h1 value hashes a manifest of the source tree, not the module
// zip; saying so is the point of the field.
func TestDigestSubjectSourceTreeRoundTrips(t *testing.T) {
	digest := Digest{Algorithm: DigestAlgorithmSHA256, Value: "abc123", Subject: DigestSubjectSourceTree}
	raw, err := json.Marshal(digest)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Digest
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != digest {
		t.Fatalf("decoded = %+v, want %+v", decoded, digest)
	}

	// A payload from a build that predates the field still decodes.
	var legacy Digest
	if err := json.Unmarshal([]byte(`{"algorithm":"sha256","value":"abc123"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Subject != DigestSubjectArtifact {
		t.Fatalf("subject = %q, want the artifact default", legacy.Subject)
	}
}

func TestPackageAttestationCloneIsDeep(t *testing.T) {
	pkg := &Package{
		Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"},
		Attestations: []PackageAttestation{{
			PredicateType: "https://slsa.dev/provenance/v1",
			Source:        "example-matcher",
			URL:           "https://registry.example.test/react/18.2.0/provenance",
			Digest:        &Digest{Algorithm: DigestAlgorithmSHA256, Value: "abc123"},
			Issuer:        "https://accounts.example.test/workflow",
			Verified:      true,
		}},
	}

	clone := pkg.Clone()
	clone.Attestations[0].Verified = false
	clone.Attestations[0].Digest.Value = "def456"
	clone.Attestations[0].Issuer = "someone-else"

	original := pkg.Attestations[0]
	if !original.Verified || original.Digest.Value != "abc123" || original.Issuer != "https://accounts.example.test/workflow" {
		t.Fatalf("mutating a clone changed the original: %+v", original)
	}
}

// Attestations survive registry deduplication when the record that wins has
// none of its own.
func TestPackageMergeFromFillsAttestations(t *testing.T) {
	pkg := &Package{Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"}}
	pkg.MergeFrom(&Package{
		Coordinates:  Coordinates{PURL: "pkg:npm/react@18.2.0"},
		Attestations: []PackageAttestation{{PredicateType: "https://slsa.dev/provenance/v1", Verified: true}},
	})

	if len(pkg.Attestations) != 1 || !pkg.Attestations[0].Verified {
		t.Fatalf("attestations = %+v, want the merged record's", pkg.Attestations)
	}

	// The merged copy must not share state with the source.
	source := &Package{
		Coordinates:  Coordinates{PURL: "pkg:npm/react@18.2.0"},
		Attestations: []PackageAttestation{{PredicateType: "https://slsa.dev/provenance/v1", Digest: &Digest{Value: "abc123"}}},
	}
	target := &Package{Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"}}
	target.MergeFrom(source)
	target.Attestations[0].Digest.Value = "def456"
	if source.Attestations[0].Digest.Value != "abc123" {
		t.Fatal("merged attestations share state with the source")
	}
}

// An empty attestation list is omitted, so payloads for the overwhelmingly
// common case are unchanged.
func TestPackageAttestationsOmittedWhenEmpty(t *testing.T) {
	raw, err := json.Marshal(&Package{Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "attestations") {
		t.Fatalf("an empty attestation list must not be serialized: %s", raw)
	}
}
