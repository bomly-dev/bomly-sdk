package sdk

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The digest algorithm registry. Both SBOM formats define a closed hash
// vocabulary, so an algorithm Bomly cannot name in the target format cannot be
// published at all -- which makes the registry, not a pair of string
// constants, the thing that decides whether a digest survives export.
//
// Canonical SDK spellings are lowercase and keep the family separator that the
// formats use ("sha3-256", not "sha3256"), so a token reads the way the
// algorithm is named in its own literature.
const (
	DigestAlgorithmMD2        DigestAlgorithm = "md2"
	DigestAlgorithmMD4        DigestAlgorithm = "md4"
	DigestAlgorithmMD5        DigestAlgorithm = "md5"
	DigestAlgorithmMD6        DigestAlgorithm = "md6"
	DigestAlgorithmSHA1       DigestAlgorithm = "sha1"
	DigestAlgorithmSHA224     DigestAlgorithm = "sha224"
	DigestAlgorithmSHA256     DigestAlgorithm = "sha256"
	DigestAlgorithmSHA384     DigestAlgorithm = "sha384"
	DigestAlgorithmSHA512     DigestAlgorithm = "sha512"
	DigestAlgorithmSHA3256    DigestAlgorithm = "sha3-256"
	DigestAlgorithmSHA3384    DigestAlgorithm = "sha3-384"
	DigestAlgorithmSHA3512    DigestAlgorithm = "sha3-512"
	DigestAlgorithmBLAKE2b256 DigestAlgorithm = "blake2b-256"
	DigestAlgorithmBLAKE2b384 DigestAlgorithm = "blake2b-384"
	DigestAlgorithmBLAKE2b512 DigestAlgorithm = "blake2b-512"
	DigestAlgorithmBLAKE3     DigestAlgorithm = "blake3"
	DigestAlgorithmADLER32    DigestAlgorithm = "adler32"
)

// digestAlgorithmProfile records one algorithm's canonical SDK token next to
// its spelling in each format. An empty format spelling means that format's
// enumeration has no such member, so a digest using it cannot be exported
// there -- SPDX 2.3 defines MD2, MD4, MD6, SHA224, and ADLER32, which
// CycloneDX does not.
type digestAlgorithmProfile struct {
	canonical DigestAlgorithm
	spdx      string
	cycloneDX string
}

// digestAlgorithmProfiles is transcribed from the two specifications'
// enumerations: SPDX 2.3's ChecksumAlgorithm and CycloneDX 1.5/1.6's hash-alg.
// Rows are not invented -- an algorithm appears here only because a format
// names it.
var digestAlgorithmProfiles = []digestAlgorithmProfile{
	{DigestAlgorithmMD2, "MD2", ""},
	{DigestAlgorithmMD4, "MD4", ""},
	{DigestAlgorithmMD5, "MD5", "MD5"},
	{DigestAlgorithmMD6, "MD6", ""},
	{DigestAlgorithmSHA1, "SHA1", "SHA-1"},
	{DigestAlgorithmSHA224, "SHA224", ""},
	{DigestAlgorithmSHA256, "SHA256", "SHA-256"},
	{DigestAlgorithmSHA384, "SHA384", "SHA-384"},
	{DigestAlgorithmSHA512, "SHA512", "SHA-512"},
	{DigestAlgorithmSHA3256, "SHA3-256", "SHA3-256"},
	{DigestAlgorithmSHA3384, "SHA3-384", "SHA3-384"},
	{DigestAlgorithmSHA3512, "SHA3-512", "SHA3-512"},
	{DigestAlgorithmBLAKE2b256, "BLAKE2b-256", "BLAKE2b-256"},
	{DigestAlgorithmBLAKE2b384, "BLAKE2b-384", "BLAKE2b-384"},
	{DigestAlgorithmBLAKE2b512, "BLAKE2b-512", "BLAKE2b-512"},
	{DigestAlgorithmBLAKE3, "BLAKE3", "BLAKE3"},
	{DigestAlgorithmADLER32, "ADLER32", ""},
}

// digestAlgorithmIndex resolves any known spelling to its canonical token.
// Keys are squashed -- lowercased with separators removed -- so the three
// spellings of one algorithm ("SHA-256", "SHA256", "sha256") resolve to one
// value without the table listing every variant. Squashing is unambiguous
// here: no two registry rows collide once separators are dropped, which
// digest_test.go asserts so a future row cannot quietly introduce one.
var digestAlgorithmIndex = buildDigestAlgorithmIndex()

func buildDigestAlgorithmIndex() map[string]DigestAlgorithm {
	index := make(map[string]DigestAlgorithm, len(digestAlgorithmProfiles)*3)
	for _, profile := range digestAlgorithmProfiles {
		for _, spelling := range []string{string(profile.canonical), profile.spdx, profile.cycloneDX} {
			if squashed := squashDigestAlgorithm(spelling); squashed != "" {
				index[squashed] = profile.canonical
			}
		}
	}
	return index
}

// maxDigestAlgorithmLength bounds an algorithm spelling. The longest
// registered name is "BLAKE2b-256" at eleven characters; the allowance leaves
// room for a separator-heavy variant without admitting a value that is
// obviously not an algorithm name. digest_test.go asserts every registered
// spelling fits, so a future row cannot silently exceed it.
const maxDigestAlgorithmLength = 64

// squashDigestAlgorithm reduces a spelling to its comparison key.
func squashDigestAlgorithm(value string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		switch r {
		case '-', '_', ' ', '.':
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ParseDigestAlgorithm resolves any spelling either format uses -- and the
// canonical SDK token -- to the canonical token. It errors on an algorithm no
// format defines, because such a digest has no export projection and a
// consumer is better told than handed a value it cannot publish.
func ParseDigestAlgorithm(value string) (DigestAlgorithm, error) {
	// Bounded before any work is done on it. Algorithm tokens arrive from
	// plugin payloads and ingested documents, and every registered spelling
	// is under 16 bytes, so a longer value cannot match -- lowercasing it and
	// building a squashed copy first would let a document of digest records
	// spend memory and CPU proportional to what it chose to send.
	if len(value) > maxDigestAlgorithmLength {
		return "", fmt.Errorf("digest algorithm is %d bytes, over the %d byte limit", len(value), maxDigestAlgorithmLength)
	}
	squashed := squashDigestAlgorithm(value)
	if squashed == "" {
		return "", fmt.Errorf("digest algorithm is empty")
	}
	algorithm, ok := digestAlgorithmIndex[squashed]
	if !ok {
		return "", fmt.Errorf("unsupported digest algorithm %q", value)
	}
	return algorithm, nil
}

// DigestAlgorithms returns every registered algorithm in canonical order.
func DigestAlgorithms() []DigestAlgorithm {
	algorithms := make([]DigestAlgorithm, 0, len(digestAlgorithmProfiles))
	for _, profile := range digestAlgorithmProfiles {
		algorithms = append(algorithms, profile.canonical)
	}
	sort.Slice(algorithms, func(i, j int) bool { return algorithms[i] < algorithms[j] })
	return algorithms
}

// profile returns the registry row for a, or false when a is not registered.
func (a DigestAlgorithm) profile() (digestAlgorithmProfile, bool) {
	for _, profile := range digestAlgorithmProfiles {
		if profile.canonical == a {
			return profile, true
		}
	}
	return digestAlgorithmProfile{}, false
}

// Valid reports whether a is a registered algorithm.
func (a DigestAlgorithm) Valid() bool {
	_, ok := a.profile()
	return ok
}

// String returns the canonical token.
func (a DigestAlgorithm) String() string { return string(a) }

// SPDXName returns the algorithm's SPDX 2.3 spelling, or "" when SPDX has no
// such member. A caller emitting a checksum must treat "" as "omit this
// digest": SPDX's algorithm field is a closed enumeration, so there is no
// spelling that would validate.
func (a DigestAlgorithm) SPDXName() string {
	profile, ok := a.profile()
	if !ok {
		return ""
	}
	return profile.spdx
}

// CycloneDXName returns the algorithm's CycloneDX 1.5/1.6 spelling, or "" when
// CycloneDX has no such member -- which is the case for the SPDX-only
// algorithms MD2, MD4, MD6, SHA224, and ADLER32. Treat "" as "omit this
// digest", as for SPDXName.
func (a DigestAlgorithm) CycloneDXName() string {
	profile, ok := a.profile()
	if !ok {
		return ""
	}
	return profile.cycloneDX
}

// maxDigestValueLength bounds a recorded digest value. The longest published
// form is a 512-bit hash in hex (128 characters); the allowance leaves room
// for the base64 and multihash spellings some ecosystems record without
// admitting a value that is plainly not a digest.
const maxDigestValueLength = 256

// Validate reports why a digest cannot be published, or nil when it can.
//
// The value itself is checked for shape, not for length-per-algorithm: the
// encoding is not fixed. Ecosystems record digests in hex, in base64 (npm's
// "sha512-..." integrity strings), and over subjects that are not files at all
// (a Go module "h1:" dirhash), so a per-algorithm hex length would reject
// values that are correct for their ecosystem.
func (d Digest) Validate() error {
	if !d.Algorithm.Valid() {
		return fmt.Errorf("unsupported digest algorithm %q", d.Algorithm)
	}
	// An unrecognized subject cannot be cleared to the zero value instead:
	// empty means "the published artifact", so treating an uninterpretable
	// label as absent would publish a claim the producer never made about
	// what the hash covers.
	if !d.Subject.Valid() {
		return fmt.Errorf("unsupported digest subject %q", d.Subject)
	}
	value := strings.TrimSpace(d.Value)
	if value == "" {
		return fmt.Errorf("digest value is empty")
	}
	if len(value) > maxDigestValueLength {
		return fmt.Errorf("digest value is %d bytes, over the %d byte limit", len(value), maxDigestValueLength)
	}
	// Invalid UTF-8 is rejected rather than carried. encoding/json replaces
	// such bytes with U+FFFD, so a digest that passed validation would
	// serialize as a different value than the one checked -- and a digest
	// that changes when written is worse than no digest.
	if !utf8.ValidString(value) {
		return fmt.Errorf("digest value is not valid UTF-8")
	}
	for _, r := range value {
		// A digest is a token. Whitespace or a control character means the
		// value was concatenated from something else, and publishing it would
		// corrupt the document it lands in. The test is Unicode-aware: an em
		// space or a next-line character is as much whitespace as a space,
		// and an ASCII-only check let those through.
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("digest value contains a control or whitespace character")
		}
	}
	return nil
}

// Normalized returns the digest with its algorithm resolved to the canonical
// token and its value trimmed, or false when the digest cannot be published.
func (d Digest) Normalized() (Digest, bool) {
	algorithm, err := ParseDigestAlgorithm(string(d.Algorithm))
	if err != nil {
		return Digest{}, false
	}
	subject, err := ParseDigestSubject(string(d.Subject))
	if err != nil {
		return Digest{}, false
	}
	normalized := Digest{Algorithm: algorithm, Value: strings.TrimSpace(d.Value), Subject: subject}
	if normalized.Validate() != nil {
		return Digest{}, false
	}
	return normalized, true
}

// digestWire carries Digest's fields without its methods, so the JSON hooks
// below can encode and decode without recursing.
type digestWire Digest

// UnmarshalJSON resolves the algorithm spelling as a value arrives, so a
// producer that wrote CycloneDX's "SHA-256" or SPDX's "SHA256" is understood
// rather than silently carried as an algorithm nothing matches. A digest that
// cannot be published decodes to the zero value, following DependencyOrigin:
// both formats close their hash enumeration, so an unpublishable digest has
// nowhere to go, and dropping it is better than failing the whole payload.
func (d *Digest) UnmarshalJSON(data []byte) error {
	var wire digestWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	normalized, ok := Digest(wire).Normalized()
	if !ok {
		*d = Digest{}
		return nil
	}
	*d = normalized
	return nil
}

// MarshalJSON applies the same rule on the way out, so a hand-built value that
// bypassed the constructors is still held to it at the wire.
func (d Digest) MarshalJSON() ([]byte, error) {
	normalized, ok := d.Normalized()
	if !ok {
		return json.Marshal(digestWire{})
	}
	return json.Marshal(digestWire(normalized))
}

// Digest captures integrity information for a package artifact.
type Digest struct {
	Algorithm DigestAlgorithm `json:"algorithm,omitempty"`
	Value     string          `json:"value,omitempty"`
	// Subject says what the digest covers. Empty means the published artifact,
	// which is what most ecosystems record and what a consumer should assume.
	// It exists because some ecosystems record a hash that is not a hash of a
	// file: a Go module's "h1:" value is SHA-256 over a manifest of the source
	// tree's file hashes, not over the module zip, so a consumer that treats it
	// as an artifact digest and compares it against a downloaded file will
	// always find a mismatch.
	//
	// Gate: ParseDigestSubject, through Digest.Normalized. The vocabulary is
	// closed, and an unrecognized subject rejects the whole digest rather
	// than being cleared -- empty is itself a claim ("the published
	// artifact"), so treating an uninterpretable label as absent would
	// publish something the producer never said.
	//
	// Merge class: part of the digest's set identity. Two records with the
	// same algorithm and value but different subjects are distinct claims and
	// both survive a union, because they say different things about what was
	// hashed.
	Subject DigestSubject `json:"subject,omitempty"`
}

// DigestSubject identifies what a digest was computed over.
type DigestSubject string

const (
	// DigestSubjectArtifact is a digest of the published file itself. It is
	// the zero value: a producer that does not say means the artifact.
	DigestSubjectArtifact DigestSubject = ""
	// DigestSubjectSourceTree is a digest over a source tree or over a
	// manifest of its file hashes, such as a Go module "h1:" dirhash.
	DigestSubjectSourceTree DigestSubject = "source-tree"
	// DigestSubjectMetadata is a digest of a package's metadata document
	// rather than of the package itself, such as a manifest or lockfile entry.
	DigestSubjectMetadata DigestSubject = "metadata"
)

// ParseDigestSubject normalizes a digest subject. The vocabulary is closed:
// Subject says what a hash covers, and it takes part in a digest's identity,
// so an unrecognized value is an integrity claim no consumer can interpret
// rather than a label to carry along.
func ParseDigestSubject(value string) (DigestSubject, error) {
	if len(value) > maxVocabularyTokenLength {
		return "", fmt.Errorf("digest subject is %d bytes, over the %d byte limit", len(value), maxVocabularyTokenLength)
	}
	switch DigestSubject(strings.ToLower(strings.TrimSpace(value))) {
	case DigestSubjectArtifact:
		return DigestSubjectArtifact, nil
	case DigestSubjectSourceTree:
		return DigestSubjectSourceTree, nil
	case DigestSubjectMetadata:
		return DigestSubjectMetadata, nil
	default:
		return "", fmt.Errorf("unsupported digest subject %q", value)
	}
}

// Valid reports whether s is a recognized subject.
func (s DigestSubject) Valid() bool {
	_, err := ParseDigestSubject(string(s))
	return err == nil
}

// String returns the subject token.
func (s DigestSubject) String() string { return string(s) }
