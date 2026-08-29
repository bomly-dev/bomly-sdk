package identitykit

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestEscapeFieldRoundTrip(t *testing.T) {
	cases := []string{
		"",
		"lodash",
		"golang.org/x/text",
		"a b",
		"100%",
		"tab\there",
		"nul\x00inside",
		"del\x7fbyte",
		"utf-8 ✓ value",
		"%20 already looks escaped",
		"truncated-utf8 caf\xc3",
		"\xff\xfe invalid bytes",
	}
	for _, value := range cases {
		escaped := EscapeField(value)
		if !utf8.ValidString(escaped) {
			t.Errorf("EscapeField(%q) = %q is not valid UTF-8 — it would not survive JSON transport", value, escaped)
		}
		for i := 0; i < len(escaped); i++ {
			// '%' is the escape introducer, so it legitimately remains; every
			// other escape-set byte must be gone.
			if c := escaped[i]; c != '%' && fieldNeedsEscape(c) {
				t.Errorf("EscapeField(%q) = %q still contains delimiter byte %#x", value, escaped, c)
			}
		}
		back, err := UnescapeField(escaped)
		if err != nil || back != value {
			t.Errorf("UnescapeField(EscapeField(%q)) = (%q, %v)", value, back, err)
		}
	}
	if got := EscapeField("a b/c%d"); got != "a%20b%2Fc%25d" {
		t.Fatalf("EscapeField pinned rendering = %q", got)
	}
	if got := EscapeField("caf\xc3"); got != "caf%C3" {
		t.Fatalf("EscapeField invalid-UTF-8 pinned rendering = %q", got)
	}
}

func TestUnescapeFieldIsStrict(t *testing.T) {
	invalid := []string{
		"a b",     // raw delimiter byte
		"a/b",     // raw joiner byte
		"a\x00b",  // raw control byte
		"a%2fb",   // lowercase hex — not the canonical spelling
		"a%2",     // truncated escape
		"a%",      // truncated escape at end
		"a%GG",    // non-hex escape
		"a%zz",    // non-hex escape
		"a%41b",   // escape of a byte with a raw canonical spelling ('A')
		"%61",     // escape of a lowercase letter — same class
		"caf\xc3", // raw invalid UTF-8 — its canonical spelling is escaped
		strings.Repeat("a", maxInputSize+1),
	}
	for _, value := range invalid {
		if got, err := UnescapeField(value); err == nil {
			t.Errorf("UnescapeField(%.20q...) = %q, want rejection", value, got)
		}
	}
}

func TestFallbackIdentityRoundTrip(t *testing.T) {
	cases := [][6]string{
		{"npm", "npm", "library", "", "lodash", "3.10.1"},
		{"go", "gomod", "library", "golang.org/x", "text", "v0.3.5"},
		{"python", "pip", "library", "", "name with space", "1.0"},
		{"npm", "npm", "library", "100%", "od%20d", "o3"},
		{"", "", "", "", "", ""},
		{"a", "b", "c", "d\x00e", "f\tg", "h\x7fi"},
	}
	for _, fields := range cases {
		id := FallbackIdentity(fields[0], fields[1], fields[2], fields[3], fields[4], fields[5])
		if !strings.HasPrefix(id, FallbackPrefix) {
			t.Fatalf("FallbackIdentity(%q) = %q lacks the family prefix", fields, id)
		}
		if strings.ContainsRune(id, rune(idDelimiter)) {
			t.Errorf("FallbackIdentity(%q) = %q contains an unescaped delimiter", fields, id)
		}
		back, ok := ParseFallbackIdentity(id)
		if !ok || back != fields {
			t.Errorf("ParseFallbackIdentity(%q) = (%q, %v), want %q", id, back, ok, fields)
		}
	}
	if got := FallbackIdentity("go", "gomod", "library", "golang.org/x", "text", "v0.3.5"); got != "coord:go/gomod/library/golang.org%2Fx/text/v0.3.5" {
		t.Fatalf("FallbackIdentity pinned rendering = %q", got)
	}
}

func TestParseFallbackIdentityRejections(t *testing.T) {
	invalid := []string{
		"",
		"pkg:npm/lodash@3.10.1",
		"coord:a/b/c/d/e",     // five fields
		"coord:a/b/c/d/e/f/g", // seven fields
		"coord:a/b/c/d/e/f%2", // truncated escape in a field
		"coord:a/b/c/d/e f/g", // raw space plus a field-count decoy
		"coord:%41/b/c/d/e/f", // non-canonical escape spelling of 'A'
		FallbackPrefix + strings.Repeat("a", maxInputSize),
	}
	for _, value := range invalid {
		if fields, ok := ParseFallbackIdentity(value); ok {
			t.Errorf("ParseFallbackIdentity(%.40q) = %q, want rejection", value, fields)
		}
	}
}

func TestOccurrenceSuffix(t *testing.T) {
	if got := OccurrenceSuffix(""); got != "" {
		t.Fatalf("OccurrenceSuffix(empty) = %q, want no suffix for the default occurrence", got)
	}
	got := OccurrenceSuffix("artifact\x00https://example.com/a.tgz")
	if len(got) != 12 || !isLowerHex(got) {
		t.Fatalf("OccurrenceSuffix = %q, want 12 lowercase hex characters", got)
	}
	if again := OccurrenceSuffix("artifact\x00https://example.com/a.tgz"); again != got {
		t.Fatal("OccurrenceSuffix is not deterministic")
	}
	if IsOccurrenceSuffix(got) != true {
		t.Fatalf("IsOccurrenceSuffix(%q) = false for a minted hash suffix", got)
	}
}

func TestOrdinalSuffix(t *testing.T) {
	cases := map[int]string{-1: "", 0: "", 1: "o1", 2: "o2", 12: "o12", 100: "o100"}
	for n, want := range cases {
		if got := OrdinalSuffix(n); got != want {
			t.Errorf("OrdinalSuffix(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestIsOccurrenceSuffix(t *testing.T) {
	valid := []string{"a1b2c3d4e5f6", "000000000000", "o1", "o10", "o999"}
	for _, s := range valid {
		if !IsOccurrenceSuffix(s) {
			t.Errorf("IsOccurrenceSuffix(%q) = false, want true", s)
		}
	}
	invalid := []string{"", "o", "o0", "o01", "oo1", "o1a", "A1B2C3D4E5F6", "a1b2c3d4e5f", "a1b2c3d4e5f67", "g1b2c3d4e5f6", "1.3.0"}
	for _, s := range invalid {
		if IsOccurrenceSuffix(s) {
			t.Errorf("IsOccurrenceSuffix(%q) = true, want false", s)
		}
	}
}

func TestJoinAndSplitID(t *testing.T) {
	base := "pkg:npm/left-pad@1.3.0"
	suffix := OccurrenceSuffix("first-party")
	joined := JoinID(base, suffix)
	if joined != base+" "+suffix {
		t.Fatalf("JoinID = %q", joined)
	}
	if gotBase, gotSuffix := SplitID(joined); gotBase != base || gotSuffix != suffix {
		t.Fatalf("SplitID(%q) = (%q, %q)", joined, gotBase, gotSuffix)
	}
	if got := JoinID(base, ""); got != base {
		t.Fatalf("JoinID with empty suffix = %q, want the base unchanged", got)
	}
	if got := JoinID("", "o1"); got != "" {
		t.Fatalf("JoinID with empty base = %q — a suffix alone is not an ID", got)
	}

	splitCases := map[string][2]string{
		"pkg:npm/a@1.0.0":                 {"pkg:npm/a@1.0.0", ""},
		"pkg:npm/a@1.0.0 o3":              {"pkg:npm/a@1.0.0", "o3"},
		"pkg:golang/example@v1#sub o3":    {"pkg:golang/example@v1#sub", "o3"},
		"coord:npm/npm/library//a/1 o1":   {"coord:npm/npm/library//a/1", "o1"},
		"pkg:npm/a@1.0.0 not-a-suffix":    {"pkg:npm/a@1.0.0 not-a-suffix", ""},
		"pkg:npm/a@1.0.0 o1 a1b2c3d4e5f6": {"pkg:npm/a@1.0.0 o1", "a1b2c3d4e5f6"},
		"":                                {"", ""},
		"o1":                              {"o1", ""},
		" a0a000000000":                   {" a0a000000000", ""},
	}
	for id, want := range splitCases {
		gotBase, gotSuffix := SplitID(id)
		if gotBase != want[0] || gotSuffix != want[1] {
			t.Errorf("SplitID(%q) = (%q, %q), want (%q, %q)", id, gotBase, gotSuffix, want[0], want[1])
		}
	}
	oversized := strings.Repeat("a", maxInputSize+1) + " o1"
	if gotBase, gotSuffix := SplitID(oversized); gotBase != oversized || gotSuffix != "" {
		t.Fatal("oversized ID was split instead of returned whole")
	}
}

func TestEphemeralIDs(t *testing.T) {
	base := "pkg:npm/a@1.0.0"
	id := EphemeralID(base, 2)
	if id != base+"\x00o2" {
		t.Fatalf("EphemeralID = %q", id)
	}
	if !IsEphemeralID(id) || IsEphemeralID(base) {
		t.Fatal("IsEphemeralID misclassifies")
	}
	if got := EphemeralBase(id); got != base {
		t.Fatalf("EphemeralBase = %q", got)
	}
	if got := EphemeralBase(base); got != base {
		t.Fatalf("EphemeralBase on a readable ID = %q, want unchanged", got)
	}
	if EphemeralID("", 1) != "" || EphemeralID(base, 0) != "" {
		t.Fatal("degenerate EphemeralID inputs must render empty, so graph insertion rejects them loudly")
	}
}

func TestEncodeFacetsV1Layout(t *testing.T) {
	pkg, occ := "pkg:npm/a@1.0.0", "first-party"
	encoded := EncodeFacetsV1(pkg, occ)
	wantLen := 12 + len(AddressTagV1) + len(pkg) + len(occ)
	if len(encoded) != wantLen {
		t.Fatalf("encoding length = %d, want %d", len(encoded), wantLen)
	}
	// Injectivity across the field boundary: a NUL-joined tuple would let
	// these collide.
	if AddressV1("a\x00b", "c") == AddressV1("a", "b\x00c") {
		t.Fatal("length-prefixed encoding is not injective across the field boundary")
	}
	if AddressV1("", "") == AddressV1("a", "") || AddressV1("a", "") == AddressV1("", "a") {
		t.Fatal("distinct facet sets share an address")
	}
	address := AddressV1(pkg, occ)
	if len(address) != 32 || !isLowerHex(address) {
		t.Fatalf("AddressV1 = %q, want 32 lowercase hex characters", address)
	}
	if again := AddressV1(pkg, occ); again != address {
		t.Fatal("AddressV1 is not deterministic")
	}
}

func TestAddressV1BoundsFacetLength(t *testing.T) {
	// The shared input bound keeps the four-byte length prefix trivially
	// faithful: a facet at the bound still encodes and hashes, one past it
	// has no encoding and no address.
	atBound := strings.Repeat("a", maxInputSize)
	if encoded := EncodeFacetsV1(atBound, ""); len(encoded) != 12+len(AddressTagV1)+len(atBound) {
		t.Fatal("facet at the bound must encode")
	}
	if address := AddressV1(atBound, ""); len(address) != 32 {
		t.Fatalf("facet at the bound must address, got %q", address)
	}
	over := atBound + "a"
	if encoded := EncodeFacetsV1(over, ""); encoded != nil {
		t.Fatal("oversized package identity encoded")
	}
	// The v1 fields are UTF-8: an invalid sequence would be rewritten to
	// U+FFFD by JSON transport and silently re-derive a different address.
	if encoded := EncodeFacetsV1("pkg:npm/a@1.0.0", "artifact\x00https://e.com/\xff.tgz"); encoded != nil {
		t.Fatal("invalid-UTF-8 facet encoded")
	}
	if address := AddressV1("\xff", ""); address != "" {
		t.Fatalf("invalid-UTF-8 facet minted address %q", address)
	}
	if encoded := EncodeFacetsV1("", over); encoded != nil {
		t.Fatal("oversized occurrence facet encoded")
	}
	if address := AddressV1(over, ""); address != "" {
		t.Fatalf("oversized facet minted address %q", address)
	}
}

// TestLeafPurity pins the package's leaf constraint: identitykit imports the
// standard library only — never the root SDK package, purlkit, or any other
// dependency — so the root package can delegate to it without a cycle and
// independent implementations need nothing beyond this directory and SPEC.md.
func TestLeafPurity(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			// cgo's import "C" has no dot but is not standard library.
			first, _, _ := strings.Cut(path, "/")
			if strings.Contains(first, ".") || path == "C" {
				t.Errorf("%s imports %q — identitykit is a leaf package and imports the standard library only", name, path)
			}
		}
	}
}
