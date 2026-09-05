package purlkit

import "testing"

// The PEP 440 canonical form is the library's call. This pins what the
// library answers for the spellings that matter to identity -- drawn from
// the PEP's own normalization section -- so an upstream change moves a test
// here rather than moving identities silently. A refused spelling stays as
// written: that is what keeps a non-Python version from being corrupted and
// an unconventional one from being dropped.
//
// If it fails after a dependency bump: the identities of every affected
// PyPI package move. Decide deliberately, then update the table.
func TestPyPIVersionCanonicalFormMatchesLibrary(t *testing.T) {
	for input, want := range map[string]string{
		// Case, and the pre-release separators and spellings PEP 440 folds.
		"1.0.0RC1":      "1.0.0rc1",
		"1.0.0rc1":      "1.0.0rc1",
		"1.0.0-rc1":     "1.0.0rc1",
		"1.0.0.RC.1":    "1.0.0rc1",
		"1.0c1":         "1.0rc1",
		"1.0pre1":       "1.0rc1",
		"1.0alpha1":     "1.0a1",
		"1.0.0-alpha.1": "1.0.0a1",
		// Post and dev releases, epochs, local segments, leading zeros and
		// the leading "v" PEP 440 permits and normalizes away.
		"1.0-post1":             "1.0.post1",
		"1.0.dev0":              "1.0.dev0",
		"1!2.0":                 "1!2.0",
		"1.0.0+LOCAL":           "1.0.0+local",
		"1.0.0rc1.dev1+abc.DEF": "1.0.0rc1.dev1+abc.def",
		"01.02":                 "1.2",
		"v1.0.0":                "1.0.0",
		// Already canonical: a fixed point.
		"2.31.0": "2.31.0",
		"2020.1": "2020.1",
		// Not PEP 440: returned exactly as written, never guessed at.
		"1.0-SNAPSHOT": "1.0-SNAPSHOT",
		"2021-03-01":   "2021-03-01",
		"1.0.*":        "1.0.*",
		"":             "",
	} {
		if got := canonicalPyPIVersion(input); got != want {
			t.Errorf("canonicalPyPIVersion(%q) = %q, want %q", input, got, want)
		}
	}
}

// The fold reaches every path an identity can take -- Build from parts,
// Parse of a stated string -- and only for the pypi type.
func TestPyPIVersionFoldsOnEveryIdentityPath(t *testing.T) {
	built, err := Build(PURL{Type: "pypi", Name: "Requests_Toolbelt", Version: "1.0.0RC1"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "pkg:pypi/requests-toolbelt@1.0.0rc1"; built != want {
		t.Fatalf("Build = %q, want %q", built, want)
	}
	if got := Canonicalize("pkg:pypi/requests-toolbelt@1.0.0RC1"); got != built {
		t.Fatalf("Parse path = %q, Build path = %q; the two must mint one identity", got, built)
	}
	// A refused version rides through unchanged, and the identity is still
	// minted -- an unconventional version is not a reason to drop a package.
	if got := Canonicalize("pkg:pypi/internal@2021-03-01"); got != "pkg:pypi/internal@2021-03-01" {
		t.Fatalf("unparseable pypi version = %q, want it left as written", got)
	}
	// Other types are untouched: Maven versions are case sensitive, and
	// 1.0-SNAPSHOT is a different version from 1.0-snapshot.
	for _, raw := range []string{
		"pkg:maven/org.example/lib@1.0-SNAPSHOT",
		"pkg:cargo/serde@1.0.0-RC1",
		"pkg:npm/left-pad@1.0.0-RC1",
		"pkg:generic/tool@1.0.0RC1?bomly_source_type=pypi",
	} {
		if got := Canonicalize(raw); got != raw {
			t.Fatalf("Canonicalize(%q) = %q, want the version left alone outside pypi", raw, got)
		}
	}
}

// The wrapper sits on an untrusted input path in front of third-party
// parsing: it must never panic, and its output must be a fixed point so the
// identity a caller stores does not canonicalize to a different key later.
func FuzzPyPIVersion(f *testing.F) {
	for _, seed := range []string{
		"1.0.0RC1", "1.0.0rc1.dev1+abc.DEF", "1!2.0", "v1.0", "01.02",
		"1.0-SNAPSHOT", "2021-03-01", "1.0.*", "", " ", "\x00", "1.0+", "!", "1e10", "9999999999999999999999.0",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > maxFuzzInputSize {
			t.Skip("input exceeds fuzz bound")
		}
		got := canonicalPyPIVersion(raw)
		if again := canonicalPyPIVersion(raw); again != got {
			t.Fatalf("not deterministic: %q vs %q", got, again)
		}
		if fixed := canonicalPyPIVersion(got); fixed != got {
			t.Fatalf("not a fixed point: %q -> %q -> %q", raw, got, fixed)
		}
		if got != raw && (got == "" || got != canonicalPyPIVersion(got)) {
			t.Fatalf("folded %q to %q, which is not itself canonical", raw, got)
		}
	})
}
