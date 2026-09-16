package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestDigestAlgorithmSquashKeysDoNotCollide guards the squashed alias index.
// Dropping separators is what lets "SHA-256", "SHA256", and "sha256" resolve
// to one value without listing every variant, and it is only sound while no
// two registry rows squash to the same key. A future row that collided would
// silently resolve one algorithm's spelling to another algorithm.
func TestDigestAlgorithmSquashKeysDoNotCollide(t *testing.T) {
	owner := make(map[string]DigestAlgorithm, len(digestAlgorithmProfiles)*3)
	for _, profile := range digestAlgorithmProfiles {
		for _, spelling := range []string{string(profile.canonical), profile.spdx, profile.cycloneDX} {
			squashed := squashDigestAlgorithm(spelling)
			if squashed == "" {
				continue
			}
			if existing, found := owner[squashed]; found && existing != profile.canonical {
				t.Fatalf("spelling %q squashes to %q, claimed by both %q and %q", spelling, squashed, existing, profile.canonical)
			}
			owner[squashed] = profile.canonical
		}
	}
}

func TestParseDigestAlgorithmAcceptsEveryFormatSpelling(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  DigestAlgorithm
	}{
		{"sha256", DigestAlgorithmSHA256},
		{"SHA256", DigestAlgorithmSHA256},  // SPDX
		{"SHA-256", DigestAlgorithmSHA256}, // CycloneDX
		{" sha-256 ", DigestAlgorithmSHA256},
		{"SHA3-512", DigestAlgorithmSHA3512},
		{"sha3512", DigestAlgorithmSHA3512},
		{"BLAKE2b-256", DigestAlgorithmBLAKE2b256},
		{"blake2b256", DigestAlgorithmBLAKE2b256},
		{"ADLER32", DigestAlgorithmADLER32},
	} {
		got, err := ParseDigestAlgorithm(tc.input)
		if err != nil {
			t.Fatalf("ParseDigestAlgorithm(%q): unexpected error %v", tc.input, err)
		}
		if got != tc.want {
			t.Fatalf("ParseDigestAlgorithm(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
	for _, input := range []string{"", "   ", "crc32", "sha257", "rot13"} {
		if got, err := ParseDigestAlgorithm(input); err == nil {
			t.Fatalf("ParseDigestAlgorithm(%q) = %q, want an error", input, got)
		}
	}
}

// TestDigestAlgorithmFormatProjections pins that an algorithm one format does
// not define reports no spelling there. A caller treats "" as "omit this
// digest"; returning the canonical token instead would emit a value that
// fails the format's own schema validation.
func TestDigestAlgorithmFormatProjections(t *testing.T) {
	if got := DigestAlgorithmSHA256.SPDXName(); got != "SHA256" {
		t.Fatalf("SHA256 SPDX name = %q, want %q", got, "SHA256")
	}
	if got := DigestAlgorithmSHA256.CycloneDXName(); got != "SHA-256" {
		t.Fatalf("SHA256 CycloneDX name = %q, want %q", got, "SHA-256")
	}
	// SPDX defines these; CycloneDX 1.5/1.6 does not.
	for _, algorithm := range []DigestAlgorithm{
		DigestAlgorithmMD2, DigestAlgorithmMD4, DigestAlgorithmMD6,
		DigestAlgorithmSHA224, DigestAlgorithmADLER32,
	} {
		if got := algorithm.SPDXName(); got == "" {
			t.Fatalf("%q has no SPDX spelling, but the registry lists it as SPDX-defined", algorithm)
		}
		if got := algorithm.CycloneDXName(); got != "" {
			t.Fatalf("%q reports CycloneDX spelling %q, but CycloneDX does not define it", algorithm, got)
		}
	}
	if got := DigestAlgorithm("not-registered").SPDXName(); got != "" {
		t.Fatalf("unregistered algorithm reported SPDX spelling %q", got)
	}
}

// TestDigestWireNormalizesForeignSpellings pins that a producer writing a
// format's own spelling is understood. Without the codec the value would be
// stored as an algorithm no comparison matches, and every digest from a
// CycloneDX-shaped producer would silently fail to deduplicate.
func TestDigestWireNormalizesForeignSpellings(t *testing.T) {
	var digest Digest
	if err := json.Unmarshal([]byte(`{"algorithm":"SHA-256","value":"abc123"}`), &digest); err != nil {
		t.Fatalf("decode digest: %v", err)
	}
	if digest.Algorithm != DigestAlgorithmSHA256 {
		t.Fatalf("decoded algorithm = %q, want %q", digest.Algorithm, DigestAlgorithmSHA256)
	}
	encoded, err := json.Marshal(digest)
	if err != nil {
		t.Fatalf("encode digest: %v", err)
	}
	if !strings.Contains(string(encoded), `"algorithm":"sha256"`) {
		t.Fatalf("encoded digest = %s, want the canonical algorithm token", encoded)
	}
}

func TestDigestWireDropsUnpublishableValues(t *testing.T) {
	for _, payload := range []string{
		`{"algorithm":"crc32","value":"abc"}`,
		`{"algorithm":"sha256","value":""}`,
		`{"algorithm":"sha256","value":"abc def"}`,
		"{\"algorithm\":\"sha256\",\"value\":\"abc\\u0000def\"}",
	} {
		var digest Digest
		if err := json.Unmarshal([]byte(payload), &digest); err != nil {
			t.Fatalf("decode %s: %v", payload, err)
		}
		if digest != (Digest{}) {
			t.Fatalf("payload %s decoded to %+v, want the zero digest", payload, digest)
		}
	}
}

// TestParseDigestAlgorithmBoundsItsInput pins the bound, and that the bound is
// comfortably above every registered spelling — a limit that clipped a real
// algorithm name would be a silent correctness bug rather than a guard.
func TestParseDigestAlgorithmBoundsItsInput(t *testing.T) {
	// The error must come from the bound, not from the registry lookup that
	// would reject it anyway: the point is that an arbitrarily large token is
	// refused before it is lowercased and copied into a squashed key, so
	// asserting only "it errors" would pass with the bound removed.
	_, err := ParseDigestAlgorithm(strings.Repeat("a", maxDigestAlgorithmLength+1))
	if err == nil {
		t.Fatal("an over-long algorithm token was accepted")
	}
	if !strings.Contains(err.Error(), "over the") {
		t.Fatalf("error = %v, want the length bound to have rejected it before the lookup", err)
	}
	for _, profile := range digestAlgorithmProfiles {
		for _, spelling := range []string{string(profile.canonical), profile.spdx, profile.cycloneDX} {
			if len(spelling) > maxDigestAlgorithmLength {
				t.Fatalf("registered spelling %q is %d bytes, over the parse limit", spelling, len(spelling))
			}
		}
	}
}

// TestDigestRejectsUnknownSubjects pins the closed subject vocabulary. An
// unrecognized subject cannot be cleared to the zero value instead: empty
// means "the published artifact", so treating an uninterpretable label as
// absent would publish a claim about what the hash covers that its producer
// never made.
func TestDigestRejectsUnknownSubjects(t *testing.T) {
	var digest Digest
	if err := json.Unmarshal([]byte(`{"algorithm":"sha256","value":"abc","subject":"archive"}`), &digest); err != nil {
		t.Fatalf("decode digest: %v", err)
	}
	if digest != (Digest{}) {
		t.Fatalf("an unknown subject decoded to %+v, want the digest dropped", digest)
	}
	// Validate reports it too, for a caller that asks directly rather than
	// going through the codec.
	if err := (Digest{Algorithm: DigestAlgorithmSHA256, Value: "abc", Subject: "archive"}).Validate(); err == nil {
		t.Fatal("Validate accepted an unknown subject")
	}
	// The three declared subjects still round-trip.
	for _, subject := range []DigestSubject{DigestSubjectArtifact, DigestSubjectSourceTree, DigestSubjectMetadata} {
		normalized, ok := Digest{Algorithm: DigestAlgorithmSHA256, Value: "abc", Subject: subject}.Normalized()
		if !ok || normalized.Subject != subject {
			t.Fatalf("subject %q was rejected: %+v ok=%v", subject, normalized, ok)
		}
	}
	// A declared subject spelled differently is normalized rather than
	// rejected: the parse is what makes the vocabulary usable, not only what
	// closes it.
	normalized, ok := Digest{Algorithm: DigestAlgorithmSHA256, Value: "abc", Subject: "  SOURCE-TREE  "}.Normalized()
	if !ok || normalized.Subject != DigestSubjectSourceTree {
		t.Fatalf("a padded, upper-case subject normalized to %+v (ok=%v), want %q", normalized, ok, DigestSubjectSourceTree)
	}
}

// TestDigestValueRejectsUnserializableRunes pins two shapes an ASCII-only
// check let through. Invalid UTF-8 is replaced by encoding/json with U+FFFD,
// so a digest that passed validation would serialize as a different value than
// the one checked; and Unicode whitespace is as much whitespace as a space.
func TestDigestValueRejectsUnserializableRunes(t *testing.T) {
	for name, value := range map[string]string{
		"invalid UTF-8": "abc\xffdef",
		"em space":      "abc\u2003def",
		"next line":     "abc\u0085def",
		"ascii space":   "abc def",
		"ascii control": "abc\x07def",
	} {
		if _, ok := (Digest{Algorithm: DigestAlgorithmSHA256, Value: value}).Normalized(); ok {
			t.Errorf("%s: an unpublishable digest value was accepted", name)
		}
	}
	// A normal hex digest is unaffected, and so is a base64 integrity value.
	for _, value := range []string{"abc123", "sha512-Zm9vYmFy+/=="} {
		if _, ok := (Digest{Algorithm: DigestAlgorithmSHA256, Value: value}).Normalized(); !ok {
			t.Errorf("a legitimate digest value %q was rejected", value)
		}
	}
}
