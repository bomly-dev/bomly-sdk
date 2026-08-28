package spdxkit

import (
	"fmt"
	"strings"

	"github.com/github/go-spdx/v2/spdxexp"
	"github.com/github/go-spdx/v2/spdxexp/spdxlicenses"
)

// maxInputSize bounds untrusted input before parsing (the repository's fuzz
// convention, enforced in production because license strings arrive from
// committed lockfiles and registry APIs and the parser's cost grows with
// input size).
const maxInputSize = 1 << 20

// maxBatchMembers bounds how many expressions one batch may carry: many
// individually small members are still one aggregate parser invocation, so
// the batch is bounded by count and by total bytes, not only per member.
const maxBatchMembers = 1024

// maxParserStructureTokens bounds recursive parser work without interpreting
// SPDX syntax ourselves. Counting delimiter and operator spellings is
// deliberately conservative; go-spdx remains the authority on validity.
const maxParserStructureTokens = 1024

// maxSatisfiesOperators bounds the expansion performed inside go-spdx's
// Satisfies implementation. A conservative count is preferable to mirroring
// the library's expression tree and distributive-expansion algorithm here.
const maxSatisfiesOperators = 16

// Valid reports whether a value within the package's safety limits parses as
// an SPDX license expression.
// Unparseable values — free text such as "non-standard", or malformed
// grouping — report false rather than failing the caller.
func Valid(expression string) bool {
	expression = strings.TrimSpace(expression)
	if expression == "" {
		return false
	}
	_, ok := normalizeExpression(expression)
	return ok
}

// ValidateAll reports whether every value within the package's aggregate and
// structural safety limits parses as an SPDX license expression, returning
// the values that do not.
func ValidateAll(values []string) (valid bool, invalid []string) {
	if len(values) == 0 {
		return true, nil
	}
	// Reject byte and count limits before any structural scan. Like a parser
	// panic, an unchecked batch cannot report any member as validated.
	if !batchWithinByteBounds(values) {
		return false, append([]string(nil), values...)
	}
	// Structurally out-of-bounds members are invalid without consulting the
	// parser; the remaining members are still checked so the invalid list stays
	// exact.
	bounded := make([]string, 0, len(values))
	for _, value := range values {
		if !withinParserBounds(value) {
			invalid = append(invalid, value)
			continue
		}
		bounded = append(bounded, value)
	}
	if len(bounded) == 0 {
		return false, invalid
	}
	oversized := invalid
	valid, invalid = validateBounded(bounded)
	invalid = append(oversized, invalid...)
	return valid && len(oversized) == 0, invalid
}

func validateBounded(values []string) (valid bool, invalid []string) {
	defer func() {
		if recover() != nil {
			// The parser gave up part-way through the batch, so no member can
			// be reported as checked.
			valid, invalid = false, append([]string(nil), values...)
		}
	}()
	return spdxexp.ValidateLicenses(values)
}

func normalizeExpression(value string) (normalized string, ok bool) {
	if !withinParserBounds(value) {
		return "", false
	}
	defer func() {
		if recover() != nil {
			normalized, ok = "", false
		}
	}()
	normalizedValues, invalid := spdxexp.ValidateAndNormalizeLicensesWithOptions(
		[]string{value}, spdxexp.ValidateLicensesOptions{})
	if len(invalid) != 0 || len(normalizedValues) != 1 {
		return "", false
	}
	return normalizedValues[0], true
}

func withinParserBounds(value string) bool {
	if len(value) > maxInputSize {
		return false
	}
	structureTokens := strings.Count(value, "(") + strings.Count(value, ")") +
		countOperatorMentions(value)
	return structureTokens <= maxParserStructureTokens
}

// countOperatorMentions counts AND/OR occurrences that can act as expression
// operators: an occurrence embedded in identifier characters on both sides —
// "OR" inside LicenseRef-OROROR — is idstring content, not an operator, and
// counting it would falsely reject a short valid expression. An occurrence
// adjacent to a delimiter on either side is counted; that over-approximates
// real operators (a bound may over-count, it must never under-count) without
// inferring grammar from arbitrary substrings.
func countOperatorMentions(value string) int {
	count := 0
	for _, operator := range []string{"AND", "OR"} {
		for offset := 0; ; {
			relative := strings.Index(value[offset:], operator)
			if relative < 0 {
				break
			}
			at := offset + relative
			after := at + len(operator)
			if operatorDelimited(value, at, after) {
				count++
			}
			offset = at + 1
		}
	}
	return count
}

func operatorDelimited(value string, start, end int) bool {
	beforeDelimited := start == 0 || isOperatorDelimiter(value[start-1])
	afterDelimited := end >= len(value) || isOperatorDelimiter(value[end])
	return beforeDelimited || afterDelimited
}

func isOperatorDelimiter(b byte) bool {
	switch b {
	// '+' is the or-later suffix, a parser-accepted token boundary in
	// compact form (GPL-2.0+ANDMIT). It cannot appear inside an idstring —
	// the grammar allows letters, digits, '.', and '-' only — so treating
	// it as a delimiter never misreads LicenseRef content as operators.
	case ' ', '\t', '\n', '\r', '(', ')', '+':
		return true
	}
	return false
}

// BatchWithinBounds reports whether a batch of license values fits the
// package's aggregate parsing limits (member count and total bytes). Callers
// that invoke classification or validation once per member — rather than
// through the batch APIs, which enforce this themselves — gate on it first,
// so a large set of individually short values cannot drive unbounded parser
// work.
func BatchWithinBounds(values []string) bool {
	return batchWithinByteBounds(values)
}

func batchWithinByteBounds(values []string) bool {
	if len(values) > maxBatchMembers {
		return false
	}
	total := 0
	for _, value := range values {
		if len(value) > maxInputSize-total {
			return false
		}
		total += len(value)
	}
	return true
}

// Identifier returns the canonical spelling of a value that is exactly one
// entry in the SPDX license list, and reports whether it is one.
//
// Compound expressions are rejected: an operator ("MIT OR Apache-2.0") is an
// expression, not a list entry, and the two are not interchangeable in
// formats that hold identifiers and expressions in separate fields. A
// trailing "+" does not by itself make a value compound — deprecated
// entries such as "GPL-2.0+" are list members and resolve here; a
// plus-suffixed value that is not a list entry ("GPL-2.0-only+", "MIT+")
// is an or-later expression and is rejected by the lookups. Deprecated
// identifiers still resolve — they remain list members; CanonicalIdentifier
// additionally folds them to their current replacements.
func Identifier(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxInputSize {
		return "", false
	}
	if strings.ContainsAny(value, " \t\n\r()") {
		return "", false
	}
	if ok, canonical := spdxlicenses.IsActiveLicense(value); ok {
		return canonical, true
	}
	if ok, canonical := spdxlicenses.IsDeprecatedLicense(value); ok {
		return canonical, true
	}
	return "", false
}

// Compose joins several license expressions into one conjunctive expression.
// A package declaring several licenses is bound by all of them, so they join
// with AND, and a compound member is parenthesized to keep its own operators
// from binding across the join.
//
// Each member is normalized through go-spdx to decide whether parentheses are
// required. Invalid members remain byte-for-byte after trimming, so composing
// free text still produces an expression that does not parse.
//
// The batch carries the same aggregate bounds as ValidateAll and Satisfies —
// each member normalization is one parser invocation. An over-count or
// over-bytes batch still composes, but parenthesization falls back to the
// whitespace heuristic instead of invoking the parser per member.
func Compose(values []string) string {
	bounded := batchWithinByteBounds(values)
	parts := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		needsParens := false
		if bounded {
			if normalized, ok := normalizeExpression(value); ok {
				needsParens = strings.Contains(normalized, " AND ") || strings.Contains(normalized, " OR ")
			}
		} else {
			// The over-limit fallback must not parse, but it must not rebind
			// either: an unparenthesized compound operand would change the
			// package assertion under AND precedence. Per the delegation
			// convention it makes no grammar guesses at all — every member
			// is parenthesized, because over-parenthesizing an atom is
			// harmless while a missing layer is not.
			needsParens = true
		}
		if needsParens {
			value = "(" + value + ")"
		}
		parts = append(parts, value)
	}
	return strings.Join(parts, " AND ")
}

// Satisfies reports whether an expression is satisfied by an allowed set.
// An unparseable expression satisfies nothing and returns the parser's error,
// or false with no error when the parser could not run at all.
func Satisfies(expression string, allowed []string) (ok bool, err error) {
	// Preflight every byte limit before structurally scanning either the
	// expression or an allowed member.
	if len(expression) > maxInputSize || !batchWithinByteBounds(allowed) {
		return false, nil
	}
	if !withinParserBounds(expression) ||
		countOperatorMentions(expression) > maxSatisfiesOperators {
		return false, nil
	}
	for _, member := range allowed {
		if !withinParserBounds(member) {
			return false, nil
		}
	}
	defer func() {
		if recover() != nil {
			ok, err = false, nil
		}
	}()
	ok, err = spdxexp.Satisfies(expression, allowed)
	if err != nil {
		return ok, fmt.Errorf("spdxkit: satisfies: %w", err)
	}
	return ok, nil
}

// Extract returns the individual license identifiers an expression uses. An
// unparseable expression returns the parser's error; an expression rejected
// by a safety limit or parser panic yields nothing and no error.
func Extract(expression string) (licenses []string, err error) {
	if !withinParserBounds(expression) {
		return nil, nil
	}
	defer func() {
		if recover() != nil {
			licenses, err = nil, nil
		}
	}()
	licenses, err = spdxexp.ExtractLicenses(expression)
	if err != nil {
		return licenses, fmt.Errorf("spdxkit: extract licenses: %w", err)
	}
	return licenses, nil
}
