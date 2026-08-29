package purlkit

import "testing"

func TestIdentityQualifierAllowlistIsEmpty(t *testing.T) {
	// Admitting the first identity-bearing qualifier key is a deliberate
	// identity-spec version bump (ADR-0036): it must ship the ADR-0033
	// credential and local-path gates for URL-valued qualifiers and
	// regenerate the identity golden vectors. This guard turns an
	// accidental addition into a reviewed act.
	if keys := IdentityQualifierKeys(); len(keys) != 0 {
		t.Fatalf("identity qualifier allowlist is no longer empty (%v) — see the guard comment before admitting keys", keys)
	}
}

func TestIdentityForm(t *testing.T) {
	cases := map[string]string{
		// Qualifiers are dropped: they carry resolution evidence, not identity.
		"pkg:maven/g/a@1?type=jar": "pkg:maven/g/a@1",
		"pkg:npm/left-pad@1.3.0?repository_url=https://registry.npmjs.org": "pkg:npm/left-pad@1.3.0",
		// The subpath names which part of the package is meant; it stays.
		"pkg:golang/example.com/mod@v1.0.0#internal/tool": "pkg:golang/example.com/mod@v1.0.0#internal/tool",
		"pkg:maven/g/a@1?classifier=sources#docs":         "pkg:maven/g/a@1#docs",
		// Qualifier-free identities pass through canonicalization only.
		"pkg:npm/%40scope/name@1.0.0": "pkg:npm/%40scope/name@1.0.0",
		"pkg:PYPI/Django@4.2":         "pkg:pypi/django@4.2",
		// Non-parsing values render empty.
		"":            "",
		"not-a-purl":  "",
		"pkg:/@1.0.0": "",
	}
	for input, want := range cases {
		if got := IdentityForm(input); got != want {
			t.Errorf("IdentityForm(%q) = %q, want %q", input, got, want)
		}
	}
}
