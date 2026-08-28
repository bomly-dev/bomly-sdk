package spdxkit

import "testing"

// maxFuzzInputSize bounds fuzz inputs before parsing, mirroring the root
// package's fuzz convention.
const maxFuzzInputSize = 1 << 20

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"MIT", "mit", "GPL-2.0", "MIT OR Apache-2.0",
		"GPL-2.0-only WITH Classpath-exception-2.0",
		"non-standard", "see LICENSE file", "(((", "", "   ",
		"MIT AND (ISC OR", "GPL-2.0+",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > maxFuzzInputSize {
			t.Skip("input exceeds fuzz bound")
		}
		// The underlying parser panics on some inputs; the contract is that
		// no panic ever escapes and results are deterministic.
		first := Classify(value)
		second := Classify(value)
		if first != second {
			t.Fatalf("Classify determinism: %v vs %v", first, second)
		}
		if first == ClassIdentifier {
			if _, ok := CanonicalIdentifier(value); !ok {
				t.Fatalf("identifier %q has no canonical form", value)
			}
		}
		_ = CanonicalExpression(value)
	})
}

func FuzzValid(f *testing.F) {
	for _, seed := range []string{"MIT", "(((", "MIT OR", "", "a AND b OR (c"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > maxFuzzInputSize {
			t.Skip("input exceeds fuzz bound")
		}
		if Valid(value) != Valid(value) {
			t.Fatal("Valid is not deterministic")
		}
		if ok, err := Satisfies(value, []string{"MIT"}); err == nil {
			_ = ok
		}
		if _, err := Extract(value); err != nil {
			_ = err
		}
	})
}

func FuzzMintLicenseRef(f *testing.F) {
	for _, seed := range []string{"see LICENSE", "", "  spaced\ttext  ", "非标准许可证"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > maxFuzzInputSize {
			t.Skip("input exceeds fuzz bound")
		}
		minted := MintLicenseRef(text)
		if minted.RefID != MintLicenseRef(text).RefID {
			t.Fatal("minting is not deterministic")
		}
		if !idstringPattern.MatchString(minted.RefID) {
			t.Fatalf("RefID %q violates the SPDX idstring charset", minted.RefID)
		}
		if minted.Text != text {
			t.Fatal("original text mutated")
		}
	})
}
