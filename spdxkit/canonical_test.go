package spdxkit

import (
	"testing"

	"github.com/github/go-spdx/v2/spdxexp/spdxlicenses"
)

func TestReplacementRows(t *testing.T) {
	// Every row of the audited map, pinned: relocated from the CLI, not
	// re-derived — the upstream list marks deprecation but does not encode
	// replacements.
	cases := map[string]string{
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
	for input, want := range cases {
		got, ok := Replacement(input)
		if !ok || got != want {
			t.Errorf("Replacement(%q) = (%q, %v), want (%q, true)", input, got, ok, want)
		}
	}
	if _, ok := Replacement("MIT"); ok {
		t.Fatal("Replacement(MIT) succeeded — active identifiers have no replacement")
	}
	if _, ok := Replacement(""); ok {
		t.Fatal("Replacement(empty) succeeded")
	}
}

func TestReplacementKeysAreUpstreamDeprecated(t *testing.T) {
	// Validity direction: every audited key must be an entry the upstream
	// list itself marks deprecated, so the map cannot drift into renaming
	// active licenses.
	for key := range replacements {
		if ok, _ := spdxlicenses.IsDeprecatedLicense(key); !ok {
			t.Errorf("replacement key %q is not deprecated upstream", key)
		}
	}
}

func TestUpstreamDeprecationsAreTriaged(t *testing.T) {
	// Every upstream deprecated entry is either mapped or deliberately
	// passed through. This pinned pass-through list makes an upstream list
	// update surface as a reviewed test change, not silence: a new upstream
	// deprecation fails here until it is triaged into one bucket.
	passThrough := map[string]struct{}{
		// Renames that are not unambiguous one-to-one replacements, or
		// entries whose replacement choice has not been audited; they pass
		// through untouched by decision.
		"BSD-2-Clause-FreeBSD":            {},
		"BSD-2-Clause-NetBSD":             {},
		"bzip2-1.0.5":                     {},
		"eCos-2.0":                        {},
		"GPL-2.0-with-autoconf-exception": {},
		"GPL-2.0-with-bison-exception":    {},
		"GPL-2.0-with-font-exception":     {},
		"GPL-2.0-with-GCC-exception":      {},
		"GPL-3.0-with-autoconf-exception": {},
		"GPL-3.0-with-GCC-exception":      {},
		"LGPL-2.0-or-later":               {},
		"LGPL-2.1-or-later":               {},
		"LGPL-3.0-or-later":               {},
		"Net-SNMP":                        {},
		"Nunit":                           {},
		"StandardML-NJ":                   {},
		"wxWindows":                       {},
		"AGPL-1.0-or-later":               {},
		"AGPL-1.0-only":                   {},
	}
	for _, deprecated := range spdxlicenses.GetDeprecated() {
		if _, mapped := replacements[deprecated]; mapped {
			continue
		}
		if _, listed := passThrough[deprecated]; listed {
			continue
		}
		t.Errorf("upstream deprecated %q is neither mapped nor triaged as pass-through", deprecated)
	}
}

func TestCanonicalIdentifier(t *testing.T) {
	if got, ok := CanonicalIdentifier("GPL-2.0"); !ok || got != "GPL-2.0-only" {
		t.Fatalf("CanonicalIdentifier(GPL-2.0) = (%q, %v)", got, ok)
	}
	if got, ok := CanonicalIdentifier("mit"); !ok || got != "MIT" {
		t.Fatalf("CanonicalIdentifier(mit) = (%q, %v)", got, ok)
	}
	if got, ok := CanonicalIdentifier("GPL-2.0-with-classpath-exception"); !ok || got != "GPL-2.0-only WITH Classpath-exception-2.0" {
		t.Fatalf("CanonicalIdentifier(classpath) = (%q, %v) — replacements may be expressions", got, ok)
	}
	if _, ok := CanonicalIdentifier("non-standard"); ok {
		t.Fatal("CanonicalIdentifier(non-standard) succeeded")
	}
}

func TestCanonicalExpression(t *testing.T) {
	cases := map[string]string{
		"GPL-2.0":                   "GPL-2.0-only",
		"(GPL-2.0 OR MIT)":          "(GPL-2.0-only OR MIT)",
		"GPL-2.0+ AND Apache-2.0":   "GPL-2.0-or-later AND Apache-2.0",
		"MIT":                       "MIT",
		"non-standard":              "non-standard",
		"":                          "",
		"GPL-2.0-only WITH GPL-2.0": "GPL-2.0-only WITH GPL-2.0-only",
	}
	for input, want := range cases {
		if got := CanonicalExpression(input); got != want {
			t.Errorf("CanonicalExpression(%q) = %q, want %q", input, got, want)
		}
	}
}
