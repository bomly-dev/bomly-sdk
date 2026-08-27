package matcherkit

import "testing"

func TestNormalizeLicenseSetClassifiesOnWrite(t *testing.T) {
	licenses := NormalizeLicenseSet([]string{
		"MIT",               // identifier: canonical spelling into SPDXExpression
		"mit",               // duplicate after canonicalization is still a distinct raw value
		"GPL-2.0",           // deprecated identifier: folds to its replacement
		"MIT OR Apache-2.0", // expression: kept, deprecated members canonicalized
		"non-standard",      // free text: SPDXExpression stays empty
		"   ",               // blank: dropped
		"MIT",               // exact duplicate: dropped
	}, "declared")

	if len(licenses) != 5 {
		t.Fatalf("got %d licenses, want 5: %+v", len(licenses), licenses)
	}
	byValue := map[string]string{}
	for _, license := range licenses {
		byValue[license.Value] = license.SPDXExpression
		if string(license.Type) != "declared" {
			t.Errorf("license %q type = %q, want declared", license.Value, license.Type)
		}
	}
	cases := map[string]string{
		"MIT":               "MIT",
		"mit":               "MIT",
		"GPL-2.0":           "GPL-2.0-only",
		"MIT OR Apache-2.0": "MIT OR Apache-2.0",
		"non-standard":      "",
	}
	for value, wantExpression := range cases {
		gotExpression, ok := byValue[value]
		if !ok {
			t.Errorf("value %q missing from output", value)
			continue
		}
		if gotExpression != wantExpression {
			t.Errorf("Value %q → SPDXExpression %q, want %q", value, gotExpression, wantExpression)
		}
	}
}

func TestNormalizeLicenseSetNeverPanicsOnHostileInput(t *testing.T) {
	// The underlying SPDX parser panics on inputs like "(((" — the spdxkit
	// guards must hold through this path too.
	licenses := NormalizeLicenseSet([]string{"((("}, "declared")
	if len(licenses) != 1 || licenses[0].SPDXExpression != "" {
		t.Fatalf("hostile input handled wrong: %+v", licenses)
	}
}
