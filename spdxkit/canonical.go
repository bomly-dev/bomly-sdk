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
	// Bound the original before tokenizing: Valid trims before checking its
	// own bound, so a huge whitespace padding around a tiny identifier
	// would otherwise pass validation and still be tokenized.
	if len(expression) > maxInputSize {
		return expression
	}
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
			segments[i].text = replacementInContext(segments, i, replacement)
			replaced = true
		}
	}
	if !replaced {
		return expression
	}
	if rewritten := joinSegments(segments); Valid(rewritten) {
		return rewritten
	}
	// Context-sensitive fallback: identifier-to-identifier replacements are
	// safe in every operand position. An expression-valued replacement is
	// also safe unless the original operand is itself followed by WITH,
	// which would create two exception applications. Apply that distinction
	// in one pass and validate once, keeping work linear in the input size.
	segments = splitExpression(expression)
	for i, segment := range segments {
		if segment.separator {
			continue
		}
		replacement, ok := Replacement(segment.text)
		if !ok {
			continue
		}
		if _, isIdentifier := Identifier(replacement); !isIdentifier && nextTokenIsWith(segments, i) {
			continue
		}
		segments[i].text = replacementInContext(segments, i, replacement)
	}
	if rewritten := joinSegments(segments); Valid(rewritten) {
		return rewritten
	}

	// Keep a future expression-valued replacement with an unanticipated
	// grammar interaction from sacrificing the always-safe identifier
	// replacements. This final candidate is still built and parsed once.
	segments = splitExpression(expression)
	for i, segment := range segments {
		if segment.separator {
			continue
		}
		replacement, ok := Replacement(segment.text)
		if !ok {
			continue
		}
		if _, isIdentifier := Identifier(replacement); isIdentifier {
			segments[i].text = replacementInContext(segments, i, replacement)
		}
	}
	if rewritten := joinSegments(segments); Valid(rewritten) {
		return rewritten
	}
	return expression
}

func nextTokenIsWith(segments []expressionSegment, current int) bool {
	for i := current + 1; i < len(segments); i++ {
		if !segments[i].separator {
			return segments[i].text == "WITH"
		}
	}
	return false
}

func replacementInContext(segments []expressionSegment, current int, replacement string) string {
	// In the permissive upstream grammar, '+' can be the only boundary
	// between a license and its following operator ("GPL-2.0+ANDMIT"). A
	// replacement ending in "-or-later" removes that boundary, so preserve
	// the tokenization with one inserted space.
	if strings.HasSuffix(segments[current].text, "+") && current+1 < len(segments) &&
		!segments[current+1].separator && isExpressionOperator(segments[current+1].text) {
		return replacement + " "
	}
	return replacement
}

func isExpressionOperator(token string) bool {
	return token == "AND" || token == "OR" || token == "WITH"
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
	separator := strings.Builder{}
	flushToken := func() {
		if token.Len() == 0 {
			return
		}
		segments = appendTokenRun(segments, token.String())
		token.Reset()
	}
	flushSeparator := func() {
		if separator.Len() == 0 {
			return
		}
		segments = append(segments, expressionSegment{separator: true, text: separator.String()})
		separator.Reset()
	}
	for _, r := range expression {
		// Treat every common whitespace rune as a token boundary. The current
		// parser accepts spaces only, but keeping the tokenizer wider prevents
		// a future parser relaxation from letting a token escape replacement.
		// Consecutive separator runes coalesce into one segment so long
		// whitespace runs cost one allocation, not one per rune.
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '(' || r == ')' {
			flushToken()
			separator.WriteRune(r)
			continue
		}
		flushSeparator()
		token.WriteRune(r)
	}
	flushToken()
	flushSeparator()
	return segments
}

func appendTokenRun(segments []expressionSegment, run string) []expressionSegment {
	for run != "" {
		matchedOperator := false
		for _, operator := range []string{"WITH", "AND", "OR"} {
			if strings.HasPrefix(run, operator) {
				segments = append(segments, expressionSegment{text: operator})
				run = run[len(operator):]
				matchedOperator = true
				break
			}
		}
		if matchedOperator {
			continue
		}
		// A plus is part of the preceding license token, but it also ends
		// that token, allowing an operator to follow without whitespace.
		end := strings.IndexByte(run, '+')
		if end < 0 {
			return append(segments, expressionSegment{text: run})
		}
		end++
		segments = append(segments, expressionSegment{text: run[:end]})
		run = run[end:]
	}
	return segments
}

func joinSegments(segments []expressionSegment) string {
	var b strings.Builder
	for _, segment := range segments {
		b.WriteString(segment.text)
	}
	return b.String()
}
