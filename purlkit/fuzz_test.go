package purlkit

import "testing"

// maxFuzzInputSize bounds fuzz inputs before parsing, mirroring the root
// package's fuzz convention.
const maxFuzzInputSize = 1 << 20

func FuzzParse(f *testing.F) {
	seeds := []string{
		"pkg:npm/left-pad@1.0.0",
		"pkg:npm/%40scope/name@2.0.0",
		"pkg:golang/github.com/google/uuid@v1.6.0",
		"pkg:golang/example.com/mod@v1#sub/dir",
		"pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie",
		"pkg:maven/g/a@1?type=jar",
		"pkg:",
		"pkg:npm",
		"not-a-purl",
		"",
		"pkg:npm/a@@1",
		"pkg:npm/%zz@1",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > maxFuzzInputSize {
			t.Skip("input exceeds fuzz bound")
		}
		parsed, err := Parse(raw)
		again, errAgain := Parse(raw)
		if (err == nil) != (errAgain == nil) {
			t.Fatalf("Parse determinism: %v vs %v", err, errAgain)
		}
		if err != nil {
			return
		}
		if parsed.String() != again.String() {
			t.Fatalf("Parse determinism: %q vs %q", parsed.String(), again.String())
		}
		// Parse → String → Parse must be a fixed point.
		rendered := parsed.String()
		if rendered == "" {
			return
		}
		reparsed, err := Parse(rendered)
		if err != nil {
			t.Fatalf("rendered form %q does not reparse: %v", rendered, err)
		}
		if reparsed.String() != rendered {
			t.Fatalf("not a fixed point: %q reparses to %q", rendered, reparsed.String())
		}
	})
}

func FuzzSplitEcosystemName(f *testing.F) {
	f.Add("npm", "@scope/name")
	f.Add("go", "github.com/google/uuid")
	f.Add("maven", "g:a")
	f.Add("apk", "alpine/libcrypto3")
	f.Add("", "")
	f.Add("hex", "phoenix")
	f.Fuzz(func(t *testing.T, ecosystem, value string) {
		if len(ecosystem) > maxFuzzInputSize || len(value) > maxFuzzInputSize {
			t.Skip("input exceeds fuzz bound")
		}
		org, name := SplitEcosystemName(ecosystem, value)
		orgAgain, nameAgain := SplitEcosystemName(ecosystem, value)
		if org != orgAgain || name != nameAgain {
			t.Fatalf("split determinism: (%q,%q) vs (%q,%q)", org, name, orgAgain, nameAgain)
		}
	})
}

func FuzzBuild(f *testing.F) {
	f.Add("A", " / 00", "0", "")
	f.Add("npm", "scope", "pkg", "1.0.0")
	f.Add("golang", "github.com/google", "uuid", "v1.6.0")
	f.Add("", "", "", "")
	f.Fuzz(func(t *testing.T, purlType, namespace, name, version string) {
		if len(purlType)+len(namespace)+len(name)+len(version) > maxFuzzInputSize {
			t.Skip("input exceeds fuzz bound")
		}
		built, err := Build(PURL{Type: purlType, Namespace: namespace, Name: name, Version: version})
		if err != nil {
			return
		}
		// Build output must be a Parse fixed point: the canonical identity a
		// caller stores must not canonicalize to a different key later.
		reparsed, err := Parse(built)
		if err != nil {
			t.Fatalf("Build output %q does not reparse: %v", built, err)
		}
		if again := reparsed.String(); again != built {
			t.Fatalf("Build output is not stable: %q reparses to %q", built, again)
		}
	})
}

func FuzzIdentityForm(f *testing.F) {
	for _, seed := range []string{
		"pkg:maven/g/a@1?type=jar",
		"pkg:npm/left-pad@1.3.0?repository_url=https://registry.npmjs.org",
		"pkg:golang/example.com/mod@v1.0.0#internal/tool",
		"pkg:maven/g/a@1?classifier=sources#docs",
		"pkg:npm/%40scope/name@1.0.0",
		"not a package url",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > maxInputSize {
			return
		}
		identity := IdentityForm(raw)
		if identity == "" {
			return
		}
		parsed, err := Parse(identity)
		if err != nil {
			t.Fatalf("identity form does not reparse: %q: %v", identity, err)
		}
		allowed := make(map[string]struct{})
		for _, key := range IdentityQualifierKeys() {
			allowed[key] = struct{}{}
		}
		for _, qualifier := range parsed.Qualifiers {
			if _, ok := allowed[qualifier.Key]; !ok {
				t.Fatalf("identity form %q kept qualifier %q outside the allowlist", identity, qualifier.Key)
			}
		}
		if again := IdentityForm(identity); again != identity {
			t.Fatalf("identity form is not a fixed point: %q then %q", identity, again)
		}
	})
}
