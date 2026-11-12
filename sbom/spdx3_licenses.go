package sbom

import (
	"strings"

	v30 "github.com/spdx/tools-golang/spdx/v3/v3_0"
)

// spdxListedLicenseNamespace is where the SPDX License List publishes its
// identifiers; an SPDX 3 listed license or exception may be named by its IRI
// there rather than carrying the identifier as its name.
const spdxListedLicenseNamespace = "https://spdx.org/licenses/"

// Operator binding strength in an SPDX license expression, weakest first: in
// the license expression grammar (SPDX 2.3 Annex D, which SPDX 3 keeps) WITH
// binds tighter than AND, which binds tighter than OR. A sub-expression is
// parenthesized only
// where it binds more weakly than the operator it appears under, so a tree
// renders as the expression a person would have written for it.
const (
	spdxPrecedenceOr = iota + 1
	spdxPrecedenceAnd
	spdxPrecedenceWith
	spdxPrecedenceAtom
)

// renderSPDX3License writes an SPDX 3 license element back as an SPDX license
// expression, the form the rest of this package reads.
//
// SPDX 3 carries a license as an object graph (the ExpandedLicensing
// profile): listed and custom licenses, an or-later operator, a WITH
// operator, and conjunctive and disjunctive sets. tools-golang parses an
// expression into that graph (v3_0.ParseLicenseExpression) but has no way
// back, and no other Go library reads it. This is that way back, and nothing
// more: each node renders as the one expression operator it stands for, and
// the string it produces is handed to spdxkit -- which owns the expression
// grammar, its validation and its canonical form -- exactly as a license
// string read from an SPDX 2.3 document is. So no grammar is owned here, and
// a malformed tree yields a string spdxkit rejects rather than a guess.
// TestSPDX3LicenseRenderingInvertsTheLibraryParser pins the round trip.
//
// ok is false when any node cannot be rendered, in which case the license is
// dropped, as an unreadable 2.3 license string is.
func renderSPDX3License(license v30.AnyLicenseInfo) (string, bool) {
	expression, _, ok := renderSPDX3LicenseNode(license)
	return expression, ok
}

func renderSPDX3LicenseNode(license v30.AnyLicenseInfo) (expression string, precedence int, ok bool) {
	if isNilElement(license) {
		return "", 0, false
	}
	switch l := license.(type) {
	case *v30.ListedLicense:
		id, ok := spdx3ListedIdentifier(l.ID, l.Name)
		return id, spdxPrecedenceAtom, ok
	case *v30.CustomLicense:
		id, ok := spdx3CustomIdentifier(l.ID, "LicenseRef-")
		return id, spdxPrecedenceAtom, ok
	case *v30.LicenseExpression:
		// A whole expression in one element; its own operators are unknown
		// here, so it is treated as the weakest-binding form and
		// parenthesized wherever it is nested.
		expression := strings.TrimSpace(l.LicenseExpression)
		return expression, spdxPrecedenceOr, expression != ""
	case *v30.IndividualLicensingInfo:
		switch l.ID {
		case v30.IndividualLicensingInfo_NoAssertionLicense.GetID():
			return "NOASSERTION", spdxPrecedenceAtom, true
		case v30.IndividualLicensingInfo_NoneLicense.GetID():
			return "NONE", spdxPrecedenceAtom, true
		}
		return "", 0, false
	case *v30.OrLaterOperator:
		subject, precedence, ok := renderSPDX3LicenseNode(l.SubjectLicense)
		if !ok || precedence != spdxPrecedenceAtom {
			return "", 0, false
		}
		return subject + "+", spdxPrecedenceAtom, true
	case *v30.WithAdditionOperator:
		subject, precedence, ok := renderSPDX3LicenseNode(l.SubjectExtendableLicense)
		if !ok || precedence != spdxPrecedenceAtom {
			return "", 0, false
		}
		addition, ok := renderSPDX3Addition(l.SubjectAddition)
		if !ok {
			return "", 0, false
		}
		return subject + " WITH " + addition, spdxPrecedenceWith, true
	case *v30.ConjunctiveLicenseSet:
		return renderSPDX3LicenseSet(l.Members, " AND ", spdxPrecedenceAnd)
	case *v30.DisjunctiveLicenseSet:
		return renderSPDX3LicenseSet(l.Members, " OR ", spdxPrecedenceOr)
	}
	return "", 0, false
}

func renderSPDX3LicenseSet(members v30.LicenseInfoList, operator string, precedence int) (string, int, bool) {
	parts := make([]string, 0, len(members))
	precedences := make([]int, 0, len(members))
	for _, member := range members {
		part, memberPrecedence, ok := renderSPDX3LicenseNode(member)
		if !ok {
			return "", 0, false
		}
		parts = append(parts, part)
		precedences = append(precedences, memberPrecedence)
	}
	switch len(parts) {
	case 0:
		return "", 0, false
	case 1:
		// A set of one is its member; there is no operator to bind.
		return parts[0], precedences[0], true
	}
	for i := range parts {
		if precedences[i] < precedence {
			parts[i] = "(" + parts[i] + ")"
		}
	}
	return strings.Join(parts, operator), precedence, true
}

func renderSPDX3Addition(addition v30.AnyLicenseAddition) (string, bool) {
	if isNilElement(addition) {
		return "", false
	}
	switch a := addition.(type) {
	case *v30.ListedLicenseException:
		// The library's parser keeps an exception's identifier in its
		// additionText; a document naming it by IRI or by name is read too.
		if id, ok := spdx3ListedIdentifier(a.ID, ""); ok {
			return id, true
		}
		if text := strings.TrimSpace(a.AdditionText); text != "" && !strings.ContainsAny(text, " \t\r\n()") {
			return text, true
		}
		return spdx3ListedIdentifier("", a.Name)
	case *v30.CustomLicenseAddition:
		return spdx3CustomIdentifier(a.ID, "AdditionRef-")
	}
	return "", false
}

// spdx3ListedIdentifier is a listed license's identifier: the tail of its
// License List IRI when it has one, otherwise its name, which is where the
// library's parser puts the identifier.
func spdx3ListedIdentifier(id, name string) (string, bool) {
	if tail, ok := strings.CutPrefix(id, spdxListedLicenseNamespace); ok && tail != "" && !strings.ContainsAny(tail, " \t\r\n()/") {
		return tail, true
	}
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, " \t\r\n()") {
		return "", false
	}
	return name, true
}

// spdx3CustomIdentifier is a custom license's or addition's reference: the
// local part of its element identifier, which the 2.3 conversion and any
// conforming producer make the LicenseRef- (or AdditionRef-) reference.
func spdx3CustomIdentifier(id, prefix string) (string, bool) {
	local := spdx3LocalName(id)
	if local == "" {
		return "", false
	}
	for _, accepted := range []string{"LicenseRef-", "AdditionRef-", "DocumentRef-"} {
		if strings.HasPrefix(local, accepted) {
			return local, true
		}
	}
	// A custom element whose identifier is not a reference -- a full IRI
	// with some other local part -- still needs one to appear in an
	// expression; the local part, made a valid idstring, is the closest the
	// document gives.
	return prefix + sanitizeSPDXID(local), true
}

// spdx3LocalName is the part of an element identifier after its namespace:
// after "#" or "/" in a full IRI, after the prefix of a compact one
// ("SPDXRef:LicenseRef-x").
func spdx3LocalName(id string) string {
	id = strings.TrimSpace(id)
	if i := strings.LastIndexAny(id, "#/:"); i >= 0 {
		return id[i+1:]
	}
	return id
}
