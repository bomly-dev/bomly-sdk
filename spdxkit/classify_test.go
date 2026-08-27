package spdxkit

import "testing"

func TestClassify(t *testing.T) {
	cases := map[string]Class{
		"MIT":               ClassIdentifier,
		"mit":               ClassIdentifier,
		"GPL-2.0":           ClassIdentifier, // deprecated entries are identifiers
		"MIT OR Apache-2.0": ClassExpression,
		"GPL-2.0-only WITH Classpath-exception-2.0": ClassExpression,
		"non-standard": ClassFreeText,
		"see LICENSE":  ClassFreeText,
		"(((":          ClassFreeText,
		"":             ClassFreeText,
		"   ":          ClassFreeText,
	}
	for input, want := range cases {
		if got := Classify(input); got != want {
			t.Errorf("Classify(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestClassifyIdentifierPrecedesExpression(t *testing.T) {
	// A bare identifier also parses as an expression; the identifier class
	// must win so formats with separate fields publish the right shape.
	if got := Classify("Apache-2.0"); got != ClassIdentifier {
		t.Fatalf("Classify(Apache-2.0) = %v, want identifier", got)
	}
}
