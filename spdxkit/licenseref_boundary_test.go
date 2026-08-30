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

// TestLicenseRefsIn pins that references are enumerated by the parser rather
// than by scanning for the prefix.
func TestLicenseRefsIn(t *testing.T) {
	for _, tc := range []struct {
		expression string
		want       int
	}{
		{"MIT", 0},
		{"LicenseRef-A", 1},
		{"MIT OR LicenseRef-A", 1},
		{"LicenseRef-A AND LicenseRef-B", 2},
		{"MIT AND LicenseRef-A AND LicenseRef-B", 2},
		// These two pin what Extract promises and LicenseRefsIn relies on:
		// it deduplicates, and it yields nothing for an expression that does
		// not parse. If either changed upstream, LicenseRefsIn would need its
		// own pass, so the dependency is asserted rather than assumed.
		{"LicenseRef-A OR LicenseRef-A", 1},
		{"LicenseRef-A OR OR", 0},
	} {
		if got := LicenseRefsIn(tc.expression); len(got) != tc.want {
			t.Errorf("LicenseRefsIn(%q) = %v, want %d references", tc.expression, got, tc.want)
		}
	}
}
