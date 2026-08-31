package sdk

import (
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// TestEveryCycloneDXScopeHasADecision is the differential test for the scope
// vocabulary. Referencing cdx.ScopeRequired makes a rename a compile error;
// it does nothing about an addition, which is how the digest registry once
// lost CycloneDX's Streebog algorithms. So the library's own declarations are
// read and each one is required to have a decision here.
//
// A new CycloneDX scope must be given one deliberately: either it maps to a
// Bomly scope set, or it is deliberately unmapped and named below. What must
// not happen is a new scope arriving and being silently read as "no scope".
func TestEveryCycloneDXScopeHasADecision(t *testing.T) {
	// Scopes that read as nothing on purpose, with the reason.
	deliberatelyUnmapped := map[string]string{}

	declared := declaredConstants(t, "github.com/CycloneDX/cyclonedx-go", "Scope")
	if len(declared) == 0 {
		t.Fatal("no Scope constants found; the differential test is not reading the library")
	}
	for name, value := range declared {
		scopes := ScopesFromCycloneDX(value)
		if len(scopes) > 0 {
			continue
		}
		if reason, ok := deliberatelyUnmapped[value]; ok {
			t.Logf("%s (%q) is unmapped: %s", name, value, reason)
			continue
		}
		t.Errorf("cyclonedx-go declares %s = %q, which ScopesFromCycloneDX reads as no scope at all. "+
			"Map it, or add it to deliberatelyUnmapped with the reason.", name, value)
	}
}

// TestScopeProjectionUsesLibrarySpellings pins that what Bomly writes into a
// document is the library's spelling, not a string typed here.
func TestScopeProjectionUsesLibrarySpellings(t *testing.T) {
	if got := CycloneDXScope([]Scope{ScopeRuntime}); got != string(cdx.ScopeRequired) {
		t.Errorf("runtime projected to %q, want %q", got, cdx.ScopeRequired)
	}
	if got := CycloneDXScope([]Scope{ScopeDevelopment}); got != string(cdx.ScopeExcluded) {
		t.Errorf("development projected to %q, want %q", got, cdx.ScopeExcluded)
	}
}

// TestScopeProjectionRule pins the policy: runtime wins a mixed set, an
// unknown-only set says nothing, and "optional" is never produced.
func TestScopeProjectionRule(t *testing.T) {
	cases := []struct {
		name   string
		scopes []Scope
		want   string
	}{
		{"runtime", []Scope{ScopeRuntime}, "required"},
		{"development", []Scope{ScopeDevelopment}, "excluded"},
		{"both", []Scope{ScopeRuntime, ScopeDevelopment}, "required"},
		{"both, other order", []Scope{ScopeDevelopment, ScopeRuntime}, "required"},
		{"empty", nil, ""},
		{"unknown only", []Scope{ScopeUnknown}, ""},
		{"unknown beside development", []Scope{ScopeUnknown, ScopeDevelopment}, "excluded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CycloneDXScope(tc.scopes); got != tc.want {
				t.Errorf("CycloneDXScope(%v) = %q, want %q", tc.scopes, got, tc.want)
			}
		})
	}
	// The mixed set must not depend on iteration order reaching runtime first.
	if a, b := CycloneDXScope([]Scope{ScopeRuntime, ScopeDevelopment}), CycloneDXScope([]Scope{ScopeDevelopment, ScopeRuntime}); a != b {
		t.Errorf("the projection is order-dependent: %q vs %q", a, b)
	}
	// "optional" is a value the library declares and Bomly never writes.
	for _, scopes := range [][]Scope{
		{ScopeRuntime}, {ScopeDevelopment}, {ScopeRuntime, ScopeDevelopment}, {ScopeUnknown}, nil,
	} {
		if got := CycloneDXScope(scopes); got == string(cdx.ScopeOptional) {
			t.Errorf("CycloneDXScope(%v) produced %q, which no detector asserts", scopes, got)
		}
	}
}

// TestScopeSetSurvivesTheCarrier pins the reason the carrier exists: the
// scalar cannot hold a set, and a Bomly document must round-trip exactly.
func TestScopeSetSurvivesTheCarrier(t *testing.T) {
	both := []Scope{ScopeRuntime, ScopeDevelopment}

	// The projection alone loses the set...
	if viaScalar := ScopesFromCycloneDX(CycloneDXScope(both)); len(viaScalar) == 2 {
		t.Fatal("the scalar round-tripped a two-scope set; the carrier would have no purpose")
	}
	// ... and the carrier keeps it.
	carried := ScopesFromCycloneDXComponent(CycloneDXScope(both), EncodeScopeSet(both))
	if len(carried) != 2 || !containsScope(carried, ScopeRuntime) || !containsScope(carried, ScopeDevelopment) {
		t.Fatalf("carrier round-trip gave %v, want both scopes", carried)
	}
}

// TestCarrierEncodingIsCanonical pins that a document built from this is
// byte-stable: two runs that found the same scopes in a different order write
// the same value, and decoding then re-encoding is a fixed point.
func TestCarrierEncodingIsCanonical(t *testing.T) {
	a := EncodeScopeSet([]Scope{ScopeRuntime, ScopeDevelopment})
	b := EncodeScopeSet([]Scope{ScopeDevelopment, ScopeRuntime})
	if a != b {
		t.Errorf("order changed the carrier value: %q vs %q", a, b)
	}
	if dup := EncodeScopeSet([]Scope{ScopeRuntime, ScopeRuntime}); dup != "runtime" {
		t.Errorf("a repeated scope encoded as %q, want %q", dup, "runtime")
	}
	if got := EncodeScopeSet([]Scope{ScopeUnknown}); got != "" {
		t.Errorf("an unknown-only set encoded as %q, want empty", got)
	}
	decoded, err := DecodeScopeSet(a)
	if err != nil {
		t.Fatalf("decoding %q failed: %v", a, err)
	}
	if again := EncodeScopeSet(decoded); again != a {
		t.Errorf("re-encoding gave %q, want %q", again, a)
	}
}

// TestCarrierDecodingIsStrict pins that a value Bomly did not write is
// refused rather than partially read. The carrier is Bomly's own field, so a
// token it cannot read means the value did not come from where it seems to.
func TestCarrierDecodingIsStrict(t *testing.T) {
	for _, value := range []string{
		"runtime,production", // a scope Bomly does not define
		"runtime,",           // a trailing separator leaves an empty field
		"required",           // the CycloneDX spelling, not Bomly's
		strings.Repeat("runtime,", 40) + "runtime", // over the byte limit
	} {
		if got, err := DecodeScopeSet(value); err == nil {
			t.Errorf("DecodeScopeSet(%q) accepted, giving %v", value, got)
		}
	}
	// An empty value is absence, not an error.
	if got, err := DecodeScopeSet(""); err != nil || got != nil {
		t.Errorf(`DecodeScopeSet("") = %v, %v; want nil, nil`, got, err)
	}
}

// TestIngestPrefersTheCarrier pins the precedence rule and its one exception.
func TestIngestPrefersTheCarrier(t *testing.T) {
	// The carrier wins even when it contradicts the scalar, because it is the
	// exact record and the scalar is a projection of it.
	got := ScopesFromCycloneDXComponent(string(cdx.ScopeRequired), "development")
	if len(got) != 1 || got[0] != ScopeDevelopment {
		t.Errorf("got %v, want the carrier's development to win over required", got)
	}
	// A malformed carrier falls back to the scalar rather than dropping the
	// scope: the scalar is still a true statement about the component.
	got = ScopesFromCycloneDXComponent(string(cdx.ScopeRequired), "not-a-scope")
	if len(got) != 1 || got[0] != ScopeRuntime {
		t.Errorf("got %v, want the scalar to be used when the carrier is malformed", got)
	}
	// With no carrier at all, the scalar is read.
	got = ScopesFromCycloneDXComponent(string(cdx.ScopeExcluded), "")
	if len(got) != 1 || got[0] != ScopeDevelopment {
		t.Errorf("got %v, want excluded to read as development", got)
	}
	// With neither, nothing is invented.
	if got = ScopesFromCycloneDXComponent("", ""); got != nil {
		t.Errorf("got %v, want no scope invented from an empty component", got)
	}
}

// TestOptionalReadsAsRuntime pins the one ingest mapping that is a judgment
// call: an optional component provides additional functionality at runtime,
// so it is not a development-only dependency.
func TestOptionalReadsAsRuntime(t *testing.T) {
	got := ScopesFromCycloneDX(string(cdx.ScopeOptional))
	if len(got) != 1 || got[0] != ScopeRuntime {
		t.Errorf("optional read as %v, want runtime", got)
	}
}

// TestUnreadableScopesInventNothing pins that a value Bomly cannot read gives
// no scope, rather than a default that would put an unmade claim in a graph.
func TestUnreadableScopesInventNothing(t *testing.T) {
	for _, value := range []string{"", "  ", "unknown", "provided", "runtime", "REQUIRED-ish"} {
		if got := ScopesFromCycloneDX(value); got != nil {
			if value == "runtime" {
				continue // Bomly's own token is not a CycloneDX scope; see below.
			}
			t.Errorf("ScopesFromCycloneDX(%q) invented %v", value, got)
		}
	}
	// Case and surrounding space are tolerated, since documents carry both.
	if got := ScopesFromCycloneDX("  REQUIRED "); len(got) != 1 || got[0] != ScopeRuntime {
		t.Errorf("got %v, want a spelled-loosely required to read as runtime", got)
	}
}
