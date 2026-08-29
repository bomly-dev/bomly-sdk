package identitykit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"unicode/utf8"
)

// AddressTagV1 is the version tag folded into every v1 content-address
// encoding. Evolving the facet set means minting a v2 tag and encoder,
// never silently changing what existing addresses hash over.
const AddressTagV1 = "bomly:node:v1"

// EncodeFacetsV1 renders the canonical v1 byte encoding of a node's
// identity facets: the version tag, the package identity, and the
// occurrence facet, in that order, each as UTF-8 bytes preceded by a
// four-byte big-endian length. An absent facet is a zero-length field,
// still length-prefixed. Length prefixes keep the encoding injective even
// when untrusted facet values contain delimiter bytes — a NUL-joined tuple
// would let ("a\x00b", "c") and ("a", "b\x00c") collide. A facet longer
// than the shared input bound, or one that is not valid UTF-8, returns nil:
// the v1 encoding defines its fields as UTF-8, and an invalid sequence
// would be rewritten to U+FFFD by JSON transport, silently re-deriving a
// different address for the same record. Real facets — canonical package
// URLs, normalized origin URLs, escaped fallback bases — are valid UTF-8
// and far below the bound by construction.
func EncodeFacetsV1(packageIdentity, occurrence string) []byte {
	fields := [3]string{AddressTagV1, packageIdentity, occurrence}
	size := 0
	for _, field := range fields {
		if len(field) > maxInputSize || !utf8.ValidString(field) {
			return nil
		}
		size += 4 + len(field)
	}
	out := make([]byte, 0, size)
	for _, field := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(field)))
		out = append(out, field...)
	}
	return out
}

// AddressV1 derives the v1 content address of a node: the SHA-256 of the
// canonical facet encoding, truncated to its first 16 bytes and rendered
// as 32 lowercase hex characters. The full 128-bit form is the canonical
// address everywhere — a shortened rendering is presentation-only and is
// never a comparison or storage key. The address identifies the stable
// occurrence class of a node, never a per-node primary key: occurrences
// distinguishable only by raw evidence share an address by design and are
// disambiguated by the graph, not the address.
// A facet over the shared input bound, or one that is not valid UTF-8,
// has no address: the empty string is returned.
func AddressV1(packageIdentity, occurrence string) string {
	encoded := EncodeFacetsV1(packageIdentity, occurrence)
	if encoded == nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:16])
}
