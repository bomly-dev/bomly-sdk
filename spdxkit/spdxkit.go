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

// Valid reports whether a value within the package's safety limits parses as
// an SPDX license expression.
// Unparseable values — free text such as "non-standard", or malformed
// grouping — report false rather than failing the caller.
func Valid(expression string) bool {
	expression = strings.TrimSpace(expression)
	if expression == "" {
		return false
	}
	valid, _ := ValidateAll([]string{expression})
	return valid
}

// ValidateAll reports whether every value within the package's aggregate and
// structural safety limits parses as an SPDX license expression, returning
// the values that do not.
func ValidateAll(values []string) (valid bool, invalid []string) {
	if len(values) == 0 {
		return true, nil
	}
	// An over-count aggregate cannot be checked at all: like a parser
	// panic, no member of it can be reported as validated.
	if len(values) > maxBatchMembers {
		return false, append([]string(nil), values...)
	}
	// Out-of-bounds members are invalid without consulting the parser; the
	// remaining members are still checked so the invalid list stays exact.
	bounded := make([]string, 0, len(values))
	boundedTotal := 0
	for _, value := range values {
		if len(value) > maxInputSize || !expressionWithinParseLimits(value) {
			invalid = append(invalid, value)
			continue
		}
		bounded = append(bounded, value)
		boundedTotal += len(value)
	}
	// Many individually small members are still one aggregate parser
	// invocation; when their total exceeds the bound the remainder is
	// wholly unchecked, so every member is reported invalid.
	if boundedTotal > maxInputSize {
		return false, append([]string(nil), values...)
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
// Callers must validate the members first: composing free text produces an
// expression that does not parse.
func Compose(values []string) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if hasCompoundOperator(value) {
			value = "(" + value + ")"
		}
		parts = append(parts, value)
	}
	return strings.Join(parts, " AND ")
}

func hasCompoundOperator(expression string) bool {
	for _, segment := range splitExpression(expression) {
		if !segment.separator && (segment.text == "AND" || segment.text == "OR") {
			return true
		}
	}
	return false
}

// Satisfies reports whether an expression is satisfied by an allowed set.
// An unparseable expression satisfies nothing and returns the parser's error,
// or false with no error when the parser could not run at all.
func Satisfies(expression string, allowed []string) (ok bool, err error) {
	if len(expression) > maxInputSize || len(allowed) > maxBatchMembers ||
		!expressionWithinParseLimits(expression) || !satisfiesWithinExpansionLimit(expression) {
		return false, nil
	}
	total := 0
	for _, member := range allowed {
		total += len(member)
		if !expressionWithinParseLimits(member) {
			return false, nil
		}
	}
	if total > maxInputSize {
		return false, nil
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
	if len(expression) > maxInputSize || !expressionWithinParseLimits(expression) {
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
