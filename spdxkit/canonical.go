package spdxkit

import "strings"

// replacements maps deprecated SPDX license identifiers onto their current
// replacements. This is Bomly's audited authority, relocated from the CLI
// (ADR-0038: relocated, not deleted): the upstream license list marks an
// entry deprecated and canonicalizes its case, but does not encode what
// replaces it — "GPL-2.0-only" for "GPL-2.0", or a license-plus-exception
// expression for "GPL-2.0-with-classpath-exception". Only unambiguous
// renames are listed; anything else passes through untouched, deliberately.
var replacements = map[string]string{
	"AGPL-1.0":                         "AGPL-1.0-only",
	"AGPL-3.0":                         "AGPL-3.0-only",
	"GFDL-1.1":                         "GFDL-1.1-only",
	"GFDL-1.2":                         "GFDL-1.2-only",
	"GFDL-1.3":                         "GFDL-1.3-only",
	"GPL-1.0":                          "GPL-1.0-only",
	"GPL-1.0+":                         "GPL-1.0-or-later",
	"GPL-2.0":                          "GPL-2.0-only",
	"GPL-2.0+":                         "GPL-2.0-or-later",
	"GPL-3.0":                          "GPL-3.0-only",
	"GPL-3.0+":                         "GPL-3.0-or-later",
	"LGPL-2.0":                         "LGPL-2.0-only",
	"LGPL-2.0+":                        "LGPL-2.0-or-later",
	"LGPL-2.1":                         "LGPL-2.1-only",
	"LGPL-2.1+":                        "LGPL-2.1-or-later",
	"LGPL-3.0":                         "LGPL-3.0-only",
	"LGPL-3.0+":                        "LGPL-3.0-or-later",
	"GPL-2.0-with-classpath-exception": "GPL-2.0-only WITH Classpath-exception-2.0",
}

// Replacement returns the current replacement for a deprecated SPDX license
// identifier, matching case-insensitively through the list's canonical
// spelling. The replacement may be an expression, not just an identifier —
// "GPL-2.0-with-classpath-exception" becomes a WITH expression.
func Replacement(deprecatedID string) (replacement string, ok bool) {
	deprecatedID = strings.TrimSpace(deprecatedID)
	if deprecatedID == "" {
		return "", false
	}
	if replacement, ok = replacements[deprecatedID]; ok {
		return replacement, true
	}
	// Fold case variants through the list's canonical spelling of the
	// deprecated entry before consulting the replacement table.
	if canonical, isEntry := Identifier(deprecatedID); isEntry {
		replacement, ok = replacements[canonical]
		return replacement, ok
	}
	return "", false
}

// CanonicalIdentifier is Identifier plus deprecated-identifier replacement:
// the one call sites use to get the current canonical spelling of a value
// that is exactly one license-list entry. A deprecated entry whose
// replacement is an expression (not a bare identifier) reports the
// expression; callers that require an identifier check the result with
// Identifier again or classify it.
func CanonicalIdentifier(value string) (canonical string, ok bool) {
	canonical, ok = Identifier(value)
	if !ok {
		return "", false
	}
	if replacement, replaced := replacements[canonical]; replaced {
		return replacement, true
	}
	return canonical, true
}

// CanonicalExpression replaces deprecated SPDX identifiers inside a license
// expression with their current names, preserving expression structure.
// Non-SPDX free-text values pass through unchanged — the whole input must
// validate as an SPDX expression before any token is rewritten, so free
// text that happens to contain a deprecated identifier ("use GPL-2.0
// here") is never corrupted. This relocates the token-wise rewriter the
// CLI's SBOM codec carried.
func CanonicalExpression(expression string) string {
	if strings.TrimSpace(expression) == "" {
		return expression
	}
	if !Valid(expression) {
		return expression
	}
	segments := splitExpression(expression)
	// Fast path: apply every replacement at once. An expression-valued
	// replacement can be invalid in context — a deprecated with-exception
	// entry as the left operand of WITH rewrites into two consecutive
	// exception applications — so the rewrite only stands if it still
	// validates.
	replaced := false
	for i, segment := range segments {
		if segment.separator {
			continue
		}
		if replacement, ok := Replacement(segment.text); ok {
			segments[i].text = replacement
			replaced = true
		}
	}
	if !replaced {
		return expression
	}
	if rewritten := joinSegments(segments); Valid(rewritten) {
		return rewritten
	}
	// Per-token fallback: a context-sensitive replacement must not cost the
	// independent ones, so each replacement is accepted individually and
	// only while the whole expression keeps validating. The result is valid
	// by construction — it starts from the valid original and every
	// accepted step re-validated.
	segments = splitExpression(expression)
	for i, segment := range segments {
		if segment.separator {
			continue
		}
		replacement, ok := Replacement(segment.text)
		if !ok {
			continue
		}
		original := segments[i].text
		segments[i].text = replacement
		if !Valid(joinSegments(segments)) {
			segments[i].text = original
		}
	}
	return joinSegments(segments)
}

// expressionSegment is one run of an expression: either a token or the
// separator bytes between tokens, preserved verbatim.
type expressionSegment struct {
	separator bool
	text      string
}

func splitExpression(expression string) []expressionSegment {
	var segments []expressionSegment
	token := strings.Builder{}
	flushToken := func() {
		if token.Len() == 0 {
			return
		}
		segments = append(segments, expressionSegment{text: token.String()})
		token.Reset()
	}
	for _, r := range expression {
		// Every whitespace separator the parser accepts is a token
		// boundary — a validated expression may use tabs or newlines
		// between tokens, and an unflushed token would escape replacement.
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '(' || r == ')' {
			flushToken()
			segments = append(segments, expressionSegment{separator: true, text: string(r)})
			continue
		}
		token.WriteRune(r)
	}
	flushToken()
	return segments
}

func joinSegments(segments []expressionSegment) string {
	var b strings.Builder
	for _, segment := range segments {
		b.WriteString(segment.text)
	}
	return b.String()
}
