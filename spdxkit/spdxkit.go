package spdxkit

import (
	"strings"

	"github.com/github/go-spdx/v2/spdxexp"
	"github.com/github/go-spdx/v2/spdxexp/spdxlicenses"
)

// maxInputSize bounds untrusted input before parsing (the repository's fuzz
// convention, enforced in production because license strings arrive from
// committed lockfiles and registry APIs and the parser's cost grows with
// input size).
const maxInputSize = 1 << 20

// Valid reports whether a value parses as an SPDX license expression.
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

// ValidateAll reports whether every value parses as an SPDX license
// expression, returning the values that do not.
func ValidateAll(values []string) (valid bool, invalid []string) {
	if len(values) == 0 {
		return true, nil
	}
	// Oversized members are invalid without consulting the parser; the
	// remaining members are still checked so the invalid list stays exact.
	bounded := make([]string, 0, len(values))
	for _, value := range values {
		if len(value) > maxInputSize {
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
		if strings.ContainsAny(value, " \t") {
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
	if len(expression) > maxInputSize {
		return false, nil
	}
	for _, member := range allowed {
		if len(member) > maxInputSize {
			return false, nil
		}
	}
	defer func() {
		if recover() != nil {
			ok, err = false, nil
		}
	}()
	return spdxexp.Satisfies(expression, allowed)
}

// Extract returns the individual license identifiers an expression uses.
// An unparseable expression yields nothing.
func Extract(expression string) (licenses []string, err error) {
	if len(expression) > maxInputSize {
		return nil, nil
	}
	defer func() {
		if recover() != nil {
			licenses, err = nil, nil
		}
	}()
	return spdxexp.ExtractLicenses(expression)
}
