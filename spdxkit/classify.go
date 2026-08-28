package spdxkit

import "strings"

// Class is the shape of a raw license value, decided by validating it.
type Class int

const (
	// ClassFreeText does not parse as SPDX: it carries as text, or as a
	// minted LicenseRef where the format demands an identifier.
	ClassFreeText Class = iota
	// ClassIdentifier is exactly one SPDX license-list entry, deprecated
	// entries included.
	ClassIdentifier
	// ClassExpression parses as an SPDX expression but is not one SPDX
	// license-list identifier. It may be compound or an atomic LicenseRef.
	ClassExpression
)

// String names the class for logs and tests.
func (c Class) String() string {
	switch c {
	case ClassIdentifier:
		return "identifier"
	case ClassExpression:
		return "expression"
	default:
		return "free-text"
	}
}

// Classify decides what a raw license value is by validating it — never by
// which field carried it (ADR-0035 in bomly-cli's dev-docs/adr). This is the
// one way a value becomes an identifier, an expression, or free text.
// Identifier is checked before expression, because a bare identifier also
// parses as an expression; deprecated identifiers classify as identifiers
// and canonicalize through CanonicalIdentifier. Empty and blank values are
// free text.
func Classify(value string) Class {
	value = strings.TrimSpace(value)
	if value == "" {
		return ClassFreeText
	}
	if _, ok := Identifier(value); ok {
		return ClassIdentifier
	}
	if Valid(value) {
		return ClassExpression
	}
	return ClassFreeText
}
