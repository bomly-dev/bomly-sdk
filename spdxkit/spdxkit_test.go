package spdxkit

import (
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	valid := []string{"MIT", "Apache-2.0", "MIT OR Apache-2.0", "GPL-2.0-only WITH Classpath-exception-2.0", "GPL-2.0"}
	for _, expr := range valid {
		if !Valid(expr) {
			t.Errorf("Valid(%q) = false, want true", expr)
		}
	}
	invalid := []string{"", "   ", "non-standard", "see LICENSE file", "((("}
	for _, expr := range invalid {
		if Valid(expr) {
			t.Errorf("Valid(%q) = true, want false", expr)
		}
	}
}

func TestValidContainsParserPanic(t *testing.T) {
	// "(((" dereferences a nil operator inside the upstream parser; the
	// whole reason this package exists is that the panic never escapes.
	if Valid("(((") {
		t.Fatal(`Valid("(((") = true`)
	}
	valid, invalid := ValidateAll([]string{"MIT", "((("})
	if valid {
		t.Fatal("ValidateAll with a panicking member reported valid")
	}
	if len(invalid) != 2 {
		// The parser gave up part-way through the batch, so no member can be
		// reported as checked.
		t.Fatalf("ValidateAll invalid = %v, want the entire batch", invalid)
	}
}

func TestIdentifier(t *testing.T) {
	if canonical, ok := Identifier("mit"); !ok || canonical != "MIT" {
		t.Fatalf("Identifier(mit) = (%q, %v)", canonical, ok)
	}
	if canonical, ok := Identifier("GPL-2.0"); !ok || canonical != "GPL-2.0" {
		t.Fatalf("Identifier(GPL-2.0) = (%q, %v) — deprecated entries remain list members", canonical, ok)
	}
	if canonical, ok := Identifier("GPL-2.0+"); !ok || canonical != "GPL-2.0+" {
		t.Fatalf("Identifier(GPL-2.0+) = (%q, %v) — plus-suffixed deprecated entries are list members", canonical, ok)
	}
	if _, ok := Identifier("MIT+"); ok {
		t.Fatal("Identifier(MIT+) succeeded — an or-later expression is not a list entry")
	}
	for _, notIdentifier := range []string{"", "MIT OR Apache-2.0", "GPL-2.0-only+", "non-standard", "(MIT)"} {
		if _, ok := Identifier(notIdentifier); ok {
			t.Errorf("Identifier(%q) succeeded, want rejection", notIdentifier)
		}
	}
}

func TestCompose(t *testing.T) {
	if got := Compose([]string{"MIT", "Apache-2.0"}); got != "MIT AND Apache-2.0" {
		t.Fatalf("Compose = %q", got)
	}
	if got := Compose([]string{"MIT OR ISC", "Apache-2.0"}); got != "(MIT OR ISC) AND Apache-2.0" {
		t.Fatalf("Compose parenthesization = %q", got)
	}
	compact := "(MIT)ORApache-2.0"
	if !Valid(compact) {
		t.Fatalf("compact-expression test fixture %q is not valid SPDX", compact)
	}
	if got := Compose([]string{compact, "ISC"}); got != "((MIT)ORApache-2.0) AND ISC" {
		t.Fatalf("Compose compact parenthesization = %q", got)
	}
	if got := Compose([]string{" ", ""}); got != "" {
		t.Fatalf("Compose(blank) = %q", got)
	}
}

func TestSatisfiesAndExtractContainPanics(t *testing.T) {
	if ok, err := Satisfies("(((", []string{"MIT"}); ok || err != nil {
		t.Fatalf("Satisfies(panic input) = (%v, %v)", ok, err)
	}
	if ok, err := Satisfies("MIT", []string{"MIT"}); !ok || err != nil {
		t.Fatalf("Satisfies(MIT, [MIT]) = (%v, %v)", ok, err)
	}
	if licenses, err := Extract("((("); licenses != nil || err != nil {
		t.Fatalf("Extract(panic input) = (%v, %v)", licenses, err)
	}
}

func TestOversizedInputsAreBounded(t *testing.T) {
	oversized := strings.Repeat("a", maxInputSize+1)
	if Valid(oversized) {
		t.Fatal("oversized expression validated")
	}
	valid, invalid := ValidateAll([]string{"MIT", oversized})
	if valid || len(invalid) != 1 || invalid[0] != oversized {
		t.Fatalf("ValidateAll(mixed oversized) = (%v, %d invalid)", valid, len(invalid))
	}
	if _, ok := Identifier(oversized); ok {
		t.Fatal("oversized identifier resolved")
	}
	if ok, _ := Satisfies(oversized, []string{"MIT"}); ok {
		t.Fatal("oversized expression satisfied")
	}
	if licenses, _ := Extract(oversized); licenses != nil {
		t.Fatal("oversized expression extracted")
	}
	if got := Classify(oversized); got != ClassFreeText {
		t.Fatalf("Classify(oversized) = %v, want free text", got)
	}
}

func TestAggregateBatchesAreBounded(t *testing.T) {
	// Many individually small members are still one aggregate parser
	// invocation; an over-limit batch is wholly unchecked, like a panic.
	big := make([]string, maxBatchMembers+1)
	for i := range big {
		big[i] = "MIT"
	}
	valid, invalid := ValidateAll(big)
	if valid || len(invalid) != len(big) {
		t.Fatalf("over-count batch = (%v, %d invalid), want whole batch invalid", valid, len(invalid))
	}
	fat := []string{strings.Repeat("a", maxInputSize/2), strings.Repeat("b", maxInputSize/2+1)}
	valid, invalid = ValidateAll(fat)
	if valid || len(invalid) != 2 {
		t.Fatalf("over-bytes batch = (%v, %d invalid), want whole batch invalid", valid, len(invalid))
	}
	if ok, _ := Satisfies("MIT", big); ok {
		t.Fatal("Satisfies accepted an over-count allowed set")
	}
}

func TestExpressionStructureIsBounded(t *testing.T) {
	deep := strings.Repeat("(", maxExpressionNesting+1) + "MIT" + strings.Repeat(")", maxExpressionNesting+1)
	if Valid(deep) {
		t.Fatal("over-nested expression validated")
	}
	manyOperators := strings.TrimSuffix(strings.Repeat("MIT AND ", maxExpressionOperators+2), " AND ")
	if Valid(manyOperators) {
		t.Fatal("expression with too many recursive operators validated")
	}
	if licenses, err := Extract(deep); licenses != nil || err != nil {
		t.Fatalf("Extract(over-nested) = (%v, %v)", licenses, err)
	}
}

func TestSatisfiesBoundsCombinatorialExpansion(t *testing.T) {
	safe := strings.TrimSuffix(strings.Repeat("(MIT OR Apache-2.0) AND ", 4), " AND ")
	if !satisfiesWithinExpansionLimit(safe) {
		t.Fatal("small expression exceeded the expansion bound")
	}
	if ok, err := Satisfies(safe, []string{"MIT", "Apache-2.0"}); !ok || err != nil {
		t.Fatalf("Satisfies(small expansion) = (%v, %v)", ok, err)
	}

	exponential := strings.TrimSuffix(strings.Repeat("(MIT OR Apache-2.0) AND ", 13), " AND ")
	if satisfiesWithinExpansionLimit(exponential) {
		t.Fatal("exponential expression passed the expansion bound")
	}
	if ok, err := Satisfies(exponential, []string{"MIT", "Apache-2.0"}); ok || err != nil {
		t.Fatalf("Satisfies(exponential) = (%v, %v), want safe rejection", ok, err)
	}
}

func TestParserErrorsCarryOperationContext(t *testing.T) {
	if _, err := Satisfies("MIT AND", []string{"MIT"}); err != nil && !strings.Contains(err.Error(), "spdxkit") {
		t.Fatalf("Satisfies error lacks operation context: %v", err)
	}
	if _, err := Extract("MIT AND"); err != nil && !strings.Contains(err.Error(), "spdxkit") {
		t.Fatalf("Extract error lacks operation context: %v", err)
	}
}
