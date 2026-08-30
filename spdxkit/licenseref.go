package spdxkit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// LicenseRefPrefix is the SPDX grammar's marker for a license identifier that
// is not on the SPDX license list. A document may define its own references
// under it, so seeing this prefix says the identifier needs accompanying
// extracted text -- not that Bomly minted it.
const LicenseRefPrefix = "LicenseRef-"

// BomlyLicenseRefPrefix marks Bomly-minted license references. The charset of
// the full reference is restricted to what the SPDX idstring grammar allows.
// A reference under this prefix is derived from its text (MintLicenseRef), so
// it is re-minted rather than trusted; a reference under LicenseRefPrefix but
// not this one was defined by the source document and is preserved as stated.
const BomlyLicenseRefPrefix = LicenseRefPrefix + "bomly-"

// licenseRefPrefix is retained as the internal spelling used when minting.
const licenseRefPrefix = BomlyLicenseRefPrefix

// ValidLicenseRef reports whether id is a well-formed SPDX license reference:
// the LicenseRef- prefix followed by a non-empty idstring, which the SPDX
// grammar restricts to letters, digits, "." and "-".
//
// This is a publication gate, not a formality. License identifiers arrive from
// untrusted documents and are written verbatim into an expression field, so a
// value carrying a space, a quote, or an operator word would either corrupt
// the emitted document or change what the expression means.
func ValidLicenseRef(id string) bool {
	if !strings.HasPrefix(id, LicenseRefPrefix) {
		return false
	}
	body := strings.TrimPrefix(id, LicenseRefPrefix)
	if body == "" || len(id) > maxLicenseRefLength {
		return false
	}
	for _, r := range body {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '-':
		default:
			return false
		}
	}
	return true
}

// maxLicenseRefLength bounds a license reference. Bomly's own minted form is
// 49 characters; the allowance leaves room for a document's own descriptive
// references without admitting an identifier that is really a payload.
const maxLicenseRefLength = 256

// ExtractedText pairs a minted license reference with the original text it
// names, ready for SPDX hasExtractedLicensingInfos and the CycloneDX
// equivalent (bomly-cli issue #410).
//
// The value is derived, never authored: Text is the authoritative half and
// RefID is a pure function of it, so the validation gate is MintLicenseRef
// itself — a value from an untrusted producer is checked with Valid, which
// re-mints from Text, and an invalid one is repaired by re-minting rather
// than trusted. Merge class: union keyed by RefID. Two values with the same
// RefID are interchangeable when valid (same normalized text mints the same
// reference), duplicates collapse, and a RefID that contradicts its Text is
// not a conflict to resolve — Text wins and the reference is re-derived.
type ExtractedText struct {
	// RefID is the minted reference: the prefix plus 32 hex characters.
	// Derived from Text; validated by Valid, repaired by MintLicenseRef.
	RefID string
	// Text is the original license text, unmodified. Authoritative: every
	// other field is recomputable from it.
	Text string
}

// Valid reports whether the reference is the one Text mints — the gate a
// consumer applies to an ExtractedText it did not mint itself.
func (e ExtractedText) Valid() bool {
	return e.RefID == MintLicenseRef(e.Text).RefID
}

// MintLicenseRef deterministically mints a license reference for a free-text
// license value: the SHA-256 of the whitespace-normalized text, truncated to
// 128 bits, hex-encoded, under the bomly LicenseRef prefix. The same text
// always mints the same reference on every run and machine — hashing keeps
// minting collision-resistant across components without coordination, and
// the output uses only characters the SPDX idstring grammar allows. The
// stored Text keeps the original value untouched; normalization applies to
// the hash input only, so texts differing merely in whitespace share a
// reference.
func MintLicenseRef(text string) ExtractedText {
	normalized := strings.Join(strings.Fields(text), " ")
	digest := sha256.Sum256([]byte(normalized))
	return ExtractedText{
		RefID: licenseRefPrefix + hex.EncodeToString(digest[:16]),
		Text:  text,
	}
}

// LicenseRefsIn returns the license references an expression names, in the
// order the parser reports them, deduplicated. It returns nil when the
// expression names none or cannot be parsed.
//
// The enumeration is the parser's, not a scan for the prefix: a reference is
// whatever SPDX's grammar says is one, and a substring match would find the
// prefix inside a quoted or malformed value that is not a reference at all.
func LicenseRefsIn(expression string) []string {
	if !strings.Contains(expression, LicenseRefPrefix) {
		return nil
	}
	// Extract is the enumeration. It parses the expression, already
	// deduplicates what it returns, and yields nothing at all when the
	// expression does not parse -- so a dedup pass or an error branch here
	// would be code that cannot change the result.
	identifiers, _ := Extract(expression)
	var refs []string
	for _, identifier := range identifiers {
		if strings.HasPrefix(identifier, LicenseRefPrefix) {
			refs = append(refs, identifier)
		}
	}
	return refs
}

// ReplaceLicenseRef rewrites every occurrence of one license reference in an
// expression, leaving the rest of the expression untouched.
//
// Replacement is boundary-aware. Identifier characters are letters, digits,
// "." and "-", so a plain substring replacement of "LicenseRef-Custom" would
// also rewrite the middle of "LicenseRef-Custom2" and silently rename a
// different license.
func ReplaceLicenseRef(expression, old, replacement string) string {
	if old == "" || !strings.Contains(expression, old) {
		return expression
	}
	var b strings.Builder
	b.Grow(len(expression))
	for i := 0; i < len(expression); {
		if !strings.HasPrefix(expression[i:], old) {
			b.WriteByte(expression[i])
			i++
			continue
		}
		beforeOK := i == 0 || !isIDStringByte(expression[i-1])
		end := i + len(old)
		afterOK := end == len(expression) || !isIDStringByte(expression[end])
		if beforeOK && afterOK {
			b.WriteString(replacement)
			i = end
			continue
		}
		b.WriteByte(expression[i])
		i++
	}
	return b.String()
}

// isIDStringByte reports whether b may appear in an SPDX idstring.
func isIDStringByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '.', b == '-':
		return true
	default:
		return false
	}
}
