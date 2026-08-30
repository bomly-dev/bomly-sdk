package spdxkit

import "testing"

// TestReplaceLicenseRef pins that replacement respects idstring boundaries.
// Identifier characters include letters, digits, "." and "-", so a plain
// substring replacement of "LicenseRef-Custom" would also rewrite the middle
// of "LicenseRef-Custom2" and silently rename a different license.
func TestReplaceLicenseRef(t *testing.T) {
	for _, tc := range []struct{ expression, old, replacement, want string }{
		{"LicenseRef-Custom", "LicenseRef-Custom", "LicenseRef-bomly-x", "LicenseRef-bomly-x"},
		{"MIT OR LicenseRef-Custom", "LicenseRef-Custom", "LicenseRef-bomly-x", "MIT OR LicenseRef-bomly-x"},
		{"(MIT OR LicenseRef-Custom)", "LicenseRef-Custom", "LicenseRef-bomly-x", "(MIT OR LicenseRef-bomly-x)"},
		// The boundary cases: a longer identifier that merely starts with the
		// one being replaced must be left alone.
		{"LicenseRef-Custom2", "LicenseRef-Custom", "LicenseRef-bomly-x", "LicenseRef-Custom2"},
		{"MIT OR LicenseRef-Custom2", "LicenseRef-Custom", "LicenseRef-bomly-x", "MIT OR LicenseRef-Custom2"},
		{"LicenseRef-Custom-extra", "LicenseRef-Custom", "LicenseRef-bomly-x", "LicenseRef-Custom-extra"},
		// ...and one whose identifier merely ends with it.
		{"XLicenseRef-Custom", "LicenseRef-Custom", "LicenseRef-bomly-x", "XLicenseRef-Custom"},
		// Both forms present: only the exact identifier is rewritten.
		{
			"LicenseRef-Custom OR LicenseRef-Custom2", "LicenseRef-Custom", "LicenseRef-bomly-x",
			"LicenseRef-bomly-x OR LicenseRef-Custom2",
		},
		{"MIT", "LicenseRef-Custom", "LicenseRef-bomly-x", "MIT"},
		{"MIT", "", "LicenseRef-bomly-x", "MIT"},
	} {
		if got := ReplaceLicenseRef(tc.expression, tc.old, tc.replacement); got != tc.want {
			t.Errorf("ReplaceLicenseRef(%q, %q, %q) = %q, want %q",
				tc.expression, tc.old, tc.replacement, got, tc.want)
		}
	}
}

// TestLicenseRefsInIsDeterministic pins the order. Extract collects
// identifiers through a map, so it reports them in an order that varies
// between runs of the same binary on the same input; CI caught this after the
// value-comparison assertion below passed locally. A caller that indexed the
// result, or a fixture that pinned it, would be flaky rather than wrong.
func TestLicenseRefsInIsDeterministic(t *testing.T) {
	const expression = "LicenseRef-B AND LicenseRef-A AND LicenseRef-C AND MIT"
	first := LicenseRefsIn(expression)
	if len(first) != 3 {
		t.Fatalf("LicenseRefsIn(%q) = %v, want three references", expression, first)
	}
	for i := 1; i < len(first); i++ {
		if first[i-1] >= first[i] {
			t.Fatalf("references are not sorted: %v", first)
		}
	}
	// Map iteration order is randomized per pass, so repeating the call is
	// what exposes an unsorted result.
	for pass := 0; pass < 200; pass++ {
		again := LicenseRefsIn(expression)
		for i := range again {
			if again[i] != first[i] {
				t.Fatalf("pass %d returned %v, want %v", pass, again, first)
			}
		}
	}
}

// TestLicenseRefsIn pins that references are enumerated by the parser rather
// than by scanning for the prefix.
func TestLicenseRefsIn(t *testing.T) {
	for _, tc := range []struct {
		expression string
		want       []string
	}{
		{"MIT", nil},
		{"LicenseRef-A", []string{"LicenseRef-A"}},
		// The identifiers matter, not their number: a filter that returned
		// "MIT" here would give the same count as one that returned the
		// reference, and only one of those is what this function promises.
		{"MIT OR LicenseRef-A", []string{"LicenseRef-A"}},
		{"LicenseRef-A AND LicenseRef-B", []string{"LicenseRef-A", "LicenseRef-B"}},
		{"MIT AND LicenseRef-A AND LicenseRef-B", []string{"LicenseRef-A", "LicenseRef-B"}},
		// These two pin what Extract promises and LicenseRefsIn relies on:
		// it deduplicates, and it yields nothing for an expression that does
		// not parse. If either changed upstream, LicenseRefsIn would need its
		// own pass, so the dependency is asserted rather than assumed.
		{"LicenseRef-A OR LicenseRef-A", []string{"LicenseRef-A"}},
		{"LicenseRef-A OR OR", nil},
	} {
		got := LicenseRefsIn(tc.expression)
		if len(got) != len(tc.want) {
			t.Errorf("LicenseRefsIn(%q) = %v, want %v", tc.expression, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("LicenseRefsIn(%q) = %v, want %v", tc.expression, got, tc.want)
				break
			}
		}
	}
}
