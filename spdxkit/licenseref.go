package spdxkit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// licenseRefPrefix marks Bomly-minted license references. The charset of the
// full reference is restricted to what the SPDX idstring grammar allows.
const licenseRefPrefix = "LicenseRef-bomly-"

// ExtractedText pairs a minted license reference with the original text it
// names, ready for SPDX hasExtractedLicensingInfos and the CycloneDX
// equivalent (bomly-cli issue #410).
type ExtractedText struct {
	// RefID is the minted reference, e.g. "LicenseRef-bomly-3b2a90c1e4d5f607".
	RefID string
	// Text is the original license text, unmodified.
	Text string
}

// MintLicenseRef deterministically mints a license reference for a free-text
// license value: the SHA-256 of the whitespace-normalized text, truncated,
// hex-encoded, under the bomly LicenseRef prefix. The same text always mints
// the same reference on every run and machine — hashing keeps minting
// collision-free across components without coordination, and the output uses
// only characters the SPDX idstring grammar allows. The stored Text keeps
// the original value untouched; normalization applies to the hash input
// only, so texts differing merely in whitespace share a reference.
func MintLicenseRef(text string) ExtractedText {
	normalized := strings.Join(strings.Fields(text), " ")
	digest := sha256.Sum256([]byte(normalized))
	return ExtractedText{
		RefID: licenseRefPrefix + hex.EncodeToString(digest[:8]),
		Text:  text,
	}
}
