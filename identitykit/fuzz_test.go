package identitykit

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// fuzzInputBound mirrors the shared testkit.MaxFuzzInputSize convention;
// identitykit cannot import testkit without breaking its leaf purity, so the
// value is pinned locally and by this comment.
const fuzzInputBound = 1 << 20

func FuzzFieldEscape(f *testing.F) {
	for _, seed := range []string{"", "lodash", "golang.org/x/text", "a b", "100%", "%20", "nul\x00byte", "utf-8 ✓"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > fuzzInputBound {
			return
		}
		escaped := EscapeField(value)
		if !utf8.ValidString(escaped) {
			t.Fatalf("escaped form %q is not valid UTF-8", escaped)
		}
		for i := 0; i < len(escaped); i++ {
			// '%' is the escape introducer and legitimately remains.
			if c := escaped[i]; c != '%' && fieldNeedsEscape(c) {
				t.Fatalf("escaped form %q contains delimiter byte %#x", escaped, c)
			}
		}
		back, err := UnescapeField(escaped)
		if err != nil {
			t.Fatalf("UnescapeField(EscapeField(%q)) failed: %v", value, err)
		}
		if back != value {
			t.Fatalf("escape round trip: %q -> %q -> %q", value, escaped, back)
		}
	})
}

func FuzzSplitID(f *testing.F) {
	f.Add("pkg:npm/left-pad@1.3.0 a1b2c3d4e5f6")
	f.Add("pkg:npm/a o12")
	f.Add("coord:npm/npm/library//org%20name/1.0")
	f.Add("a%20b c")
	f.Add("pkg:golang/example@v1#sub o3")
	f.Add("pkg:npm/a@1.0.0 o1 a1b2c3d4e5f6")
	f.Add("")
	f.Fuzz(func(t *testing.T, id string) {
		if len(id) > fuzzInputBound {
			return
		}
		base, suffix := SplitID(id)
		if suffix == "" {
			if base != id {
				t.Fatalf("SplitID(%q) dropped bytes without a suffix: base %q", id, base)
			}
			return
		}
		if !IsOccurrenceSuffix(suffix) {
			t.Fatalf("SplitID(%q) returned non-suffix %q", id, suffix)
		}
		if rejoined := JoinID(base, suffix); rejoined != id {
			t.Fatalf("JoinID(SplitID(%q)) = %q", id, rejoined)
		}
		// Splitting is deterministic and single-pass: re-splitting the base
		// never yields the same suffix boundary back.
		if again, againSuffix := SplitID(JoinID(base, suffix)); again != base || againSuffix != suffix {
			t.Fatalf("SplitID is not stable on %q", id)
		}
	})
}

func FuzzFallbackIdentity(f *testing.F) {
	f.Add("npm", "npm", "library", "", "lodash", "3.10.1")
	f.Add("go", "gomod", "library", "golang.org/x", "text", "v0.3.5")
	f.Add("python", "pip", "library", "org name", "100%", "o3")
	f.Add("", "", "", "", "", "")
	f.Add("a", "b", "c", "d\x00e", "f\tg", "h\x7fi")
	f.Add("caf\xc3", "\xff", "", "", "", "")
	f.Fuzz(func(t *testing.T, ecosystem, packageManager, pkgType, org, name, version string) {
		total := len(ecosystem) + len(packageManager) + len(pkgType) + len(org) + len(name) + len(version)
		if total > fuzzInputBound/4 {
			return
		}
		fields := [6]string{ecosystem, packageManager, pkgType, org, name, version}
		id := FallbackIdentity(fields[0], fields[1], fields[2], fields[3], fields[4], fields[5])
		if strings.ContainsAny(id, " \x00") {
			t.Fatalf("fallback rendering %q contains an unescaped delimiter or control byte", id)
		}
		back, ok := ParseFallbackIdentity(id)
		if !ok || back != fields {
			t.Fatalf("parse(render(%q)) = (%q, %v)", fields, back, ok)
		}
		// Render is a parse fixed point.
		if again := FallbackIdentity(back[0], back[1], back[2], back[3], back[4], back[5]); again != id {
			t.Fatalf("render is not a fixed point: %q vs %q", id, again)
		}
	})
}

func FuzzAddressV1(f *testing.F) {
	f.Add("pkg:npm/left-pad@1.3.0", "")
	f.Add("pkg:npm/left-pad@1.3.0", "first-party")
	f.Add("coord:npm/npm/library//lodash/3.10.1", "artifact\x00https://example.com/a.tgz")
	f.Add("", "")
	f.Add("caf\xc3", "\xff")
	f.Fuzz(func(t *testing.T, packageIdentity, occurrence string) {
		if len(packageIdentity) > fuzzInputBound || len(occurrence) > fuzzInputBound {
			return
		}
		encoded := EncodeFacetsV1(packageIdentity, occurrence)
		if !utf8.ValidString(packageIdentity) || !utf8.ValidString(occurrence) {
			if encoded != nil || AddressV1(packageIdentity, occurrence) != "" {
				t.Fatal("invalid-UTF-8 facets must have no encoding and no address")
			}
			return
		}
		wantLen := 12 + len(AddressTagV1) + len(packageIdentity) + len(occurrence)
		if len(encoded) != wantLen {
			t.Fatalf("encoding length = %d, want %d", len(encoded), wantLen)
		}
		address := AddressV1(packageIdentity, occurrence)
		if len(address) != 32 || !isLowerHex(address) {
			t.Fatalf("AddressV1 = %q, want 32 lowercase hex characters", address)
		}
		if again := AddressV1(packageIdentity, occurrence); again != address {
			t.Fatal("AddressV1 is not deterministic")
		}
	})
}
