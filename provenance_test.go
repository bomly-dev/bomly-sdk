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

// Several components can attest to one package, so merging unions rather than
// keeping whichever arrived first.
func TestPackageMergeFromUnionsAttestations(t *testing.T) {
	pkg := &Package{
		Coordinates:  Coordinates{PURL: "pkg:npm/react@18.2.0"},
		Attestations: []PackageAttestation{{Source: "provenance-matcher", PredicateType: "https://slsa.dev/provenance/v1", URL: "https://example.test/provenance"}},
	}
	pkg.MergeFrom(&Package{
		Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"},
		Attestations: []PackageAttestation{
			{Source: "signature-matcher", PredicateType: "https://in-toto.io/attestation/release/v0.1", URL: "https://example.test/release"},
			// The same statement the first record already carries, now verified.
			{Source: "provenance-matcher", PredicateType: "https://slsa.dev/provenance/v1", URL: "https://example.test/provenance", Verified: true},
		},
	})

	if len(pkg.Attestations) != 2 {
		t.Fatalf("attestations = %d, want both distinct statements: %+v", len(pkg.Attestations), pkg.Attestations)
	}
	if !pkg.Attestations[0].Verified {
		t.Fatal("a statement another component verified must end up verified")
	}
	if pkg.Attestations[1].PredicateType != "https://in-toto.io/attestation/release/v0.1" {
		t.Fatalf("second attestation = %+v, want the signature statement", pkg.Attestations[1])
	}
}

// Statements differing only by digest are different statements.
func TestPackageMergeFromKeepsDistinctDigests(t *testing.T) {
	pkg := &Package{
		Coordinates:  Coordinates{PURL: "pkg:npm/react@18.2.0"},
		Attestations: []PackageAttestation{{Source: "m", URL: "https://example.test/p", Digest: &Digest{Algorithm: DigestAlgorithmSHA256, Value: "aaa"}}},
	}
	pkg.MergeFrom(&Package{
		Coordinates:  Coordinates{PURL: "pkg:npm/react@18.2.0"},
		Attestations: []PackageAttestation{{Source: "m", URL: "https://example.test/p", Digest: &Digest{Algorithm: DigestAlgorithmSHA256, Value: "bbb"}}},
	})

	if len(pkg.Attestations) != 2 {
		t.Fatalf("attestations = %d, want two: statements with different digests are different", len(pkg.Attestations))
	}
}

// Verification belongs to whoever performed it. A record naming one issuer must
// never come out verified because a different issuer verified something else.
func TestPackageMergeFromKeepsVerificationWithItsIssuer(t *testing.T) {
	statement := func(issuer string, verified bool) PackageAttestation {
		return PackageAttestation{
			Source:        "provenance-matcher",
			PredicateType: "https://slsa.dev/provenance/v1",
			URL:           "https://example.test/provenance",
			Issuer:        issuer,
			Verified:      verified,
		}
	}

	t.Run("different issuers stay separate", func(t *testing.T) {
		pkg := &Package{Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"}, Attestations: []PackageAttestation{statement("issuer-a", false)}}
		pkg.MergeFrom(&Package{Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"}, Attestations: []PackageAttestation{statement("issuer-b", true)}})

		if len(pkg.Attestations) != 2 {
			t.Fatalf("attestations = %+v, want both issuers kept", pkg.Attestations)
		}
		for _, attestation := range pkg.Attestations {
			if attestation.Issuer == "issuer-a" && attestation.Verified {
				t.Fatal("issuer-a's statement was marked verified by issuer-b's verification")
			}
		}
	})

	// A verification recorded without a signer is its own claim. Attaching it
	// to an issuer named by a different record would say that issuer's
	// signature was checked, which nobody established.
	t.Run("an issuerless verification is not attributed to a later issuer", func(t *testing.T) {
		pkg := &Package{Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"}, Attestations: []PackageAttestation{statement("", true)}}
		pkg.MergeFrom(&Package{Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"}, Attestations: []PackageAttestation{statement("issuer-a", false)}})

		if len(pkg.Attestations) != 2 {
			t.Fatalf("attestations = %+v, want the issuerless verification kept separate", pkg.Attestations)
		}
		for _, attestation := range pkg.Attestations {
			if attestation.Issuer == "issuer-a" && attestation.Verified {
				t.Fatal("issuer-a was reported verified on the strength of a verification that named no signer")
			}
		}
	})

	// The same, with the records arriving the other way round.
	t.Run("merge order does not change the outcome", func(t *testing.T) {
		pkg := &Package{Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"}, Attestations: []PackageAttestation{statement("issuer-a", false)}}
		pkg.MergeFrom(&Package{Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"}, Attestations: []PackageAttestation{statement("", true)}})

		if len(pkg.Attestations) != 2 {
			t.Fatalf("attestations = %+v, want the issuerless verification kept separate", pkg.Attestations)
		}
		for _, attestation := range pkg.Attestations {
			if attestation.Issuer == "issuer-a" && attestation.Verified {
				t.Fatal("issuer-a was reported verified on the strength of a verification that named no signer")
			}
		}
	})

	// A record with no issuer and no verification asserts only that the
	// statement exists, so it folds into one that says more.
	t.Run("a record claiming nothing folds away", func(t *testing.T) {
		for _, order := range []string{"weak first", "weak second"} {
			t.Run(order, func(t *testing.T) {
				weak, strong := statement("", false), statement("issuer-a", true)
				first, second := weak, strong
				if order == "weak second" {
					first, second = strong, weak
				}
				pkg := &Package{Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"}, Attestations: []PackageAttestation{first}}
				pkg.MergeFrom(&Package{Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"}, Attestations: []PackageAttestation{second}})

				if len(pkg.Attestations) != 1 {
					t.Fatalf("attestations = %+v, want one record", pkg.Attestations)
				}
				if !pkg.Attestations[0].Verified || pkg.Attestations[0].Issuer != "issuer-a" {
					t.Fatalf("attestation = %+v, want verified and attributed to issuer-a", pkg.Attestations[0])
				}
			})
		}
	})

	// One issuer, two records: verification is additive, because both records
	// speak about the same signer.
	t.Run("one issuer verified in a later record", func(t *testing.T) {
		pkg := &Package{Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"}, Attestations: []PackageAttestation{statement("issuer-a", false)}}
		pkg.MergeFrom(&Package{Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"}, Attestations: []PackageAttestation{statement("issuer-a", true)}})

		if len(pkg.Attestations) != 1 {
			t.Fatalf("attestations = %+v, want one record for one issuer", pkg.Attestations)
		}
		if !pkg.Attestations[0].Verified || pkg.Attestations[0].Issuer != "issuer-a" {
			t.Fatalf("attestation = %+v, want issuer-a verified", pkg.Attestations[0])
		}
	})

	t.Run("an unknown issuer is filled from the verified record", func(t *testing.T) {
		pkg := &Package{Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"}, Attestations: []PackageAttestation{statement("", false)}}
		pkg.MergeFrom(&Package{Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"}, Attestations: []PackageAttestation{statement("issuer-b", true)}})

		if len(pkg.Attestations) != 1 {
			t.Fatalf("attestations = %+v, want one record", pkg.Attestations)
		}
		if !pkg.Attestations[0].Verified || pkg.Attestations[0].Issuer != "issuer-b" {
			t.Fatalf("attestation = %+v, want verified and attributed to issuer-b", pkg.Attestations[0])
		}
	})
}

// Statements differing only by what their digest covers are different claims.
func TestPackageMergeFromKeepsDistinctDigestSubjects(t *testing.T) {
	pkg := &Package{
		Coordinates:  Coordinates{PURL: "pkg:golang/example.test/mod@1.0.0"},
		Attestations: []PackageAttestation{{Source: "m", URL: "https://example.test/p", Digest: &Digest{Algorithm: DigestAlgorithmSHA256, Value: "aaa"}}},
	}
	pkg.MergeFrom(&Package{
		Coordinates:  Coordinates{PURL: "pkg:golang/example.test/mod@1.0.0"},
		Attestations: []PackageAttestation{{Source: "m", URL: "https://example.test/p", Digest: &Digest{Algorithm: DigestAlgorithmSHA256, Value: "aaa", Subject: DigestSubjectSourceTree}}},
	})

	if len(pkg.Attestations) != 2 {
		t.Fatalf("attestations = %d, want two: one covers the artifact, one the source tree", len(pkg.Attestations))
	}
}

// Two sources can carry different claims about one package: a hash of the
// published artifact from one, a hash over the source tree from another.
// Keeping only the first slice would lose provenance on merge order alone.
func TestPackageMergeFromUnionsDigests(t *testing.T) {
	artifact := Digest{Algorithm: DigestAlgorithmSHA256, Value: "aaa"}
	sourceTree := Digest{Algorithm: DigestAlgorithmSHA256, Value: "aaa", Subject: DigestSubjectSourceTree}

	pkg := &Package{Coordinates: Coordinates{PURL: "pkg:golang/example.test/mod@1.0.0"}, Digests: []Digest{artifact}}
	pkg.MergeFrom(&Package{Coordinates: Coordinates{PURL: "pkg:golang/example.test/mod@1.0.0"}, Digests: []Digest{sourceTree, artifact}})

	if len(pkg.Digests) != 2 {
		t.Fatalf("digests = %+v, want both claims kept and the repeat dropped", pkg.Digests)
	}
	var subjects []DigestSubject
	for _, digest := range pkg.Digests {
		subjects = append(subjects, digest.Subject)
	}
	if subjects[0] != DigestSubjectArtifact || subjects[1] != DigestSubjectSourceTree {
		t.Fatalf("subjects = %v, want the artifact claim then the source-tree claim", subjects)
	}
}
