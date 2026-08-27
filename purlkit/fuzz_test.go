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
