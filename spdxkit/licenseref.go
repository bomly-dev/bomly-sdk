package spdxkit

import (
	"crypto/sha256"
	"encoding/hex"
	"unicode"
	"unicode/utf8"
)

// licenseRefPrefix marks Bomly-minted license references. The charset of the
// full reference is restricted to what the SPDX idstring grammar allows.
const licenseRefPrefix = "LicenseRef-bomly-"

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
	digest := normalizedTextDigest(text)
	return ExtractedText{
		RefID: licenseRefPrefix + hex.EncodeToString(digest[:16]),
		Text:  text,
	}
}

func normalizedTextDigest(text string) [sha256.Size]byte {
	h := sha256.New()
	var buffer [4096]byte
	writeString := func(value string) {
		for value != "" {
			n := copy(buffer[:], value)
			_, _ = h.Write(buffer[:n])
			value = value[n:]
		}
	}
	fieldStart := -1
	wroteField := false
	flushField := func(end int) {
		if fieldStart < 0 {
			return
		}
		if wroteField {
			buffer[0] = ' '
			_, _ = h.Write(buffer[:1])
		}
		writeString(text[fieldStart:end])
		wroteField = true
		fieldStart = -1
	}

	for offset := 0; offset < len(text); {
		r, size := utf8.DecodeRuneInString(text[offset:])
		if unicode.IsSpace(r) {
			flushField(offset)
		} else if fieldStart < 0 {
			fieldStart = offset
		}
		offset += size
	}
	flushField(len(text))

	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return digest
}
