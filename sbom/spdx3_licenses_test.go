package sbom

import (
	"testing"

	v30 "github.com/spdx/tools-golang/spdx/v3/v3_0"

	"github.com/bomly-dev/bomly-sdk/spdxkit"
	testkit "github.com/bomly-dev/bomly-sdk/testkit"
)

// spdx3LicenseSeeds cover every node the library's parser builds: listed and
// custom licenses, or-later, WITH with a listed exception, both sets nested
// both ways, and the two individual values.
var spdx3LicenseSeeds = []string{
	"MIT",
	"MIT OR Apache-2.0",
	"MIT AND Apache-2.0",
	"MIT OR Apache-2.0 AND BSD-3-Clause",
	"(MIT OR Apache-2.0) AND BSD-3-Clause",
	"GPL-2.0-only WITH Classpath-exception-2.0",
	"Apache-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0",
	"GPL-2.0+",
	"LicenseRef-custom",
	"LicenseRef-custom AND (MIT OR ISC)",
	"NOASSERTION",
	"NONE",
}

// Rendering inverts the library's parser up to the canonical form spdxkit
// owns: an expression, parsed into the SPDX 3 object graph and rendered back,
// means what it meant. This is the differential test the hand-written
// renderer is held to.
func TestSPDX3LicenseRenderingInvertsTheLibraryParser(t *testing.T) {
	for _, expression := range spdx3LicenseSeeds {
		t.Run(expression, func(t *testing.T) {
			parsed, err := v30.ParseLicenseExpression(expression)
			if err != nil {
				t.Fatalf("the library cannot parse %q: %v", expression, err)
			}
			rendered, ok := renderSPDX3License(parsed)
			if !ok {
				t.Fatalf("%q did not render", expression)
			}
			if got, want := spdxkit.CanonicalExpression(rendered), spdxkit.CanonicalExpression(expression); got != want {
				t.Errorf("rendered %q (canonical %q), want canonical %q", rendered, got, want)
			}
		})
	}
}

// FuzzRenderSPDX3License drives the renderer with every tree the library's
// parser can build. The renderer reads untrusted documents, so it must never
// panic, must be deterministic, and must not turn a valid expression into an
// invalid one.
func FuzzRenderSPDX3License(f *testing.F) {
	for _, seed := range spdx3LicenseSeeds {
		f.Add(seed)
	}
	for _, seed := range []string{"", "(", "MIT OR", "MIT WITH", "A AND (B OR (C WITH D))", "LicenseRef-", "+", "MIT++"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, expression string) {
		if len(expression) > testkit.MaxFuzzInputSize {
			return
		}
		parsed, ok := parseSPDX3LicenseForFuzz(expression)
		if !ok {
			return
		}
		first, firstOK := renderSPDX3License(parsed)
		second, secondOK := renderSPDX3License(parsed)
		if first != second || firstOK != secondOK {
			t.Fatalf("non-deterministic render of %q: %q/%v then %q/%v", expression, first, firstOK, second, secondOK)
		}
		if firstOK && spdxkit.Valid(expression) && !spdxkit.Valid(first) {
			t.Fatalf("valid %q rendered as invalid %q", expression, first)
		}
	})
}

// parseSPDX3LicenseForFuzz runs the library's parser, which is not under
// test here: a panic or an error inside it is skipped, so the fuzzer spends
// its time on the renderer.
func parseSPDX3LicenseForFuzz(expression string) (parsed v30.AnyLicenseInfo, ok bool) {
	defer func() {
		if recover() != nil {
			parsed, ok = nil, false
		}
	}()
	parsed, err := v30.ParseLicenseExpression(expression)
	if err != nil || isNilElement(parsed) {
		return nil, false
	}
	return parsed, true
}
