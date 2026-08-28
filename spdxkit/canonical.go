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

// CanonicalExpression returns go-spdx's normalized rendering of a license
// expression with deprecated identifiers replaced by their current names.
// Valid input may therefore lose redundant parentheses or spacing. Non-SPDX
// free-text values pass through unchanged — the whole input must validate
// before any identifier is rewritten, so text that happens to contain a
// deprecated identifier ("use GPL-2.0 here") is never corrupted.
func CanonicalExpression(expression string) string {
	// Bound the original before normalization: callers may deliberately want
	// invalid or free-text input returned byte-for-byte.
	if len(expression) > maxInputSize {
		return expression
	}
	normalized, ok := normalizeExpression(expression)
	if !ok {
		return expression
	}
	rewritten, replaced := rewriteNormalizedExpression(normalized)
	if !replaced {
		return normalized
	}
	if canonical, ok := normalizeExpression(rewritten); ok {
		return canonical
	}
	return normalized
}

// rewriteNormalizedExpression replaces whole identifiers in go-spdx's
// canonical rendering. It is intentionally not a general SPDX tokenizer:
// go-spdx has already validated and normalized operators, whitespace, and
// parentheses before this adapter runs.
func rewriteNormalizedExpression(expression string) (rewritten string, replaced bool) {
	var b strings.Builder
	b.Grow(len(expression))
	for start := 0; start < len(expression); {
		if expression[start] == ' ' || expression[start] == '(' || expression[start] == ')' {
			b.WriteByte(expression[start])
			start++
			continue
		}
		end := start
		for end < len(expression) && expression[end] != ' ' && expression[end] != '(' && expression[end] != ')' {
			end++
		}
		token := expression[start:end]
		replacement, ok := replacements[token]
		// Replacing an atomic deprecated with-exception identifier on the
		// left of WITH would create two exception applications. The original
		// normalized token is already valid, so retain it in that context.
		if ok && strings.Contains(replacement, " ") && strings.HasPrefix(expression[end:], " WITH ") {
			ok = false
		}
		if ok {
			b.WriteString(replacement)
			replaced = true
		} else {
			b.WriteString(token)
		}
		start = end
	}
	return b.String(), replaced
}
