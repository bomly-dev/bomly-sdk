package sdk

import (
	"encoding/json"
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

// ADR-0037: unknown tokens in a carrier are dropped with a warning, not the
// whole value. The strict reading made a carrier saying "runtime,future" yield
// no scopes at all, so a component the document scoped runtime became
// unscoped and a runtime filter dropped it -- total on SPDX, which has no
// scalar to fall back to. The scopes an old build can read are still true.
func TestCarrierDecodingIsLenientAboutUnknownTokens(t *testing.T) {
	decoded, err := DecodeScopeSetLenient("runtime,future,development,future")
	if err != nil {
		t.Fatal(err)
	}
	if want := ScopesOf(ScopeDevelopment, ScopeRuntime); EncodeScopeSet(decoded.Scopes) != EncodeScopeSet(want) {
		t.Errorf("Scopes = %v, want the known scopes kept, sorted", decoded.Scopes)
	}
	if len(decoded.Unknown) != 1 || decoded.Unknown[0] != "future" {
		t.Errorf("Unknown = %v, want the one unread token, once", decoded.Unknown)
	}
	// Every token read: nothing to warn about.
	if decoded, err := DecodeScopeSetLenient("runtime"); err != nil || len(decoded.Unknown) != 0 {
		t.Errorf("DecodeScopeSetLenient(\"runtime\") = %+v, %v; want no unknown tokens", decoded, err)
	}
	// Structure a carrier would never have is still an error, not a warning:
	// the value did not come from where the caller thinks it did. That
	// includes an entry that is not shaped like a scope token -- a future
	// scope looks like "runtime", not like "bad token" -- so a malformed
	// carrier cannot override a valid scalar or surface garbage as a warning.
	for _, value := range []string{
		"runtime,", ",", strings.Repeat("runtime,", 40) + "runtime",
		"runtime,bad token", "runtime,\x01", "runtime,bad\xffutf8", "runtime,dev/opt",
		"runtime," + strings.Repeat("f", maxVocabularyTokenLength+1),
		// The Kelvin sign lowercases to ASCII "k": the shape is checked on
		// the spelling as written, so folding cannot launder a malformed
		// entry into a well-shaped one.
		"development,\u212a", "runtime,\u212aelvin",
		// A control character at a field's edge is refused before trimming
		// could shed it: a carrier is a single-line value, and a line break
		// in it is corruption, not padding -- around a known token as much
		// as an unknown one.
		"runtime,\nfuture", "runtime,\tfuture", "runtime,\ndevelopment", "\nruntime",
		// Trimming is Unicode-aware, so the rule is the class -- printable
		// ASCII -- not a list of characters: a C1 next-line control, a
		// no-break space, and an em space were all shed by TrimSpace before
		// the shape check saw the field.
		"development,\u0085future", "runtime,\u00a0future", "runtime,\u2003development", "\u00a0runtime",
	} {
		if decoded, err := DecodeScopeSetLenient(value); err == nil {
			t.Errorf("DecodeScopeSetLenient(%q) accepted, giving %+v", value, decoded)
		}
	}
	// A well-shaped unknown token is reported the way ParseScope would have
	// read it, whatever case it was written in.
	if decoded, err := DecodeScopeSetLenient("runtime,Future-Scope"); err != nil || len(decoded.Unknown) != 1 || decoded.Unknown[0] != "future-scope" {
		t.Errorf("DecodeScopeSetLenient(\"runtime,Future-Scope\") = %+v, %v; want the token reported lowercased", decoded, err)
	}
	// An empty value is absence.
	if decoded, err := DecodeScopeSetLenient(""); err != nil || decoded.Scopes != nil || decoded.Unknown != nil {
		t.Errorf(`DecodeScopeSetLenient("") = %+v, %v; want nothing`, decoded, err)
	}
	// The strict reading is the lenient one with one more rule, so the two
	// agree on every value that has no unknown token.
	strict, err := DecodeScopeSet("development,runtime")
	if err != nil || EncodeScopeSet(strict) != "development,runtime" {
		t.Errorf("DecodeScopeSet = %v, %v", strict, err)
	}

	// Ingest keeps the known scopes rather than falling back to the scalar
	// when a carrier carries a token this build does not know...
	got := ScopesFromCycloneDXComponent(string(cdx.ScopeExcluded), "runtime,future")
	if len(got) != 1 || got[0] != ScopeRuntime {
		t.Errorf("got %v, want the carrier's runtime kept over the scalar", got)
	}
	// ... and only falls back when the carrier names nothing it knows...
	got = ScopesFromCycloneDXComponent(string(cdx.ScopeExcluded), "future")
	if len(got) != 1 || got[0] != ScopeDevelopment {
		t.Errorf("got %v, want the scalar when the carrier names nothing known", got)
	}
	// ... or is malformed, however much of it happens to be readable.
	got = ScopesFromCycloneDXComponent(string(cdx.ScopeExcluded), "runtime,bad token")
	if len(got) != 1 || got[0] != ScopeDevelopment {
		t.Errorf("got %v, want the scalar when the carrier is malformed", got)
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
	// With neither, CycloneDX's default for an unspecified scope applies.
	got = ScopesFromCycloneDXComponent("", "")
	if len(got) != 1 || got[0] != ScopeRuntime {
		t.Errorf("got %v, want an unscoped component to take the required default", got)
	}
	// A carrier that reads as nothing does not suppress that default either:
	// the component still stated no scope, and the specification says what an
	// unspecified scope means.
	got = ScopesFromCycloneDXComponent("", "not-a-scope")
	if len(got) != 1 || got[0] != ScopeRuntime {
		t.Errorf("got %v, want the default to survive an unreadable carrier", got)
	}
}

// TestOptionalReadsAsDevelopment pins the mapping the specification settles:
// a CycloneDX "optional" component is one "not capable of being called due to
// [it] not being installed or otherwise accessible by any means", and one that
// is installed but prohibited from being called "must be scoped as
// 'required'". An optional component is therefore absent from what runs, which
// is what Bomly's development scope means to a filter.
//
// This is the resolution of bomly-dev/bomly-sdk#63, which the SDK previously
// read the other way on a pre-1.6 gloss of "optional". The test is here so
// that reading cannot come back by accident.
func TestOptionalReadsAsDevelopment(t *testing.T) {
	got := ScopesFromCycloneDX(string(cdx.ScopeOptional))
	if len(got) != 1 || got[0] != ScopeDevelopment {
		t.Errorf("optional read as %v, want development", got)
	}
	// Only "required" reads as runtime, and it is the sole such value.
	for _, value := range []cdx.Scope{cdx.ScopeOptional, cdx.ScopeExcluded} {
		if got := ScopesFromCycloneDX(string(value)); len(got) != 1 || got[0] != ScopeDevelopment {
			t.Errorf("%q read as %v, want development", value, got)
		}
	}
	if got := ScopesFromCycloneDX(string(cdx.ScopeRequired)); len(got) != 1 || got[0] != ScopeRuntime {
		t.Errorf("required read as %v, want runtime", got)
	}
}

// TestAnAbsentScopeTakesTheSpecifiedDefault pins the other half of the
// specification's reading: scope is an optional attribute, and CycloneDX says
// "required" scope "SHOULD be assumed by the consumer of the BOM" when it is
// not specified -- the schema restates it as a "required" default. An absent
// attribute decodes to the empty string, so that is what "not specified"
// looks like at this boundary.
//
// Before this, an unscoped component came back with no scope at all and was
// dropped by a runtime filter. Most documents Bomly did not write omit the
// attribute entirely, so that was a false negative on the common case rather
// than on an edge one.
func TestAnAbsentScopeTakesTheSpecifiedDefault(t *testing.T) {
	// Absent, and the shapes an absent attribute takes after decoding.
	for _, value := range []string{"", " ", "   ", "\t"} {
		got := ScopesFromCycloneDX(value)
		if len(got) != 1 || got[0] != ScopeRuntime {
			t.Errorf("ScopesFromCycloneDX(%q) = %v, want the required default", value, got)
		}
	}
	// The default is for an unspecified scope only. A value that is present
	// but unreadable has an unknown meaning rather than a defaulted one, so
	// it still yields nothing -- see TestUnreadableScopesInventNothing.
	if got := ScopesFromCycloneDX("compile"); got != nil {
		t.Errorf("ScopesFromCycloneDX(\"compile\") = %v, want no scope rather than the default", got)
	}
}

// TestUnreadableScopesInventNothing pins that a value Bomly cannot read gives
// no scope, rather than a default that would put an unmade claim in a graph.
// An absent value is a different case with a different answer, which is
// TestAnAbsentScopeTakesTheSpecifiedDefault's.
func TestUnreadableScopesInventNothing(t *testing.T) {
	for _, value := range []string{"unknown", "provided", "runtime", "REQUIRED-ish"} {
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

// ADR-0037: an ingested scope scalar is re-emitted verbatim on export unless
// Bomly's own scope set changed, so "optional" and "excluded" never collapse
// across a round trip that asserted neither.
//
// What the field prevents, rather than what it does: a CycloneDX "optional"
// ingests as {development}, and projecting that set on its own would write
// "excluded". The assertions below are the behavior with the field -- the
// word survives, so "optional" goes in and "optional" comes back out.
func TestSourceScopeSurvivesARoundTripUnlessTheSetChanged(t *testing.T) {
	node := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "left-pad", Version: "1.3.0"})
	node.Scopes = ScopesFromCycloneDX("optional")
	node.SourceScope = "optional"

	// Unchanged set: the source's own word comes back.
	if got := CycloneDXScopeForExport(node.Scopes, node.SourceScope); got != string(cdx.ScopeOptional) {
		t.Fatalf("export = %q, want the source's %q re-emitted", got, cdx.ScopeOptional)
	}
	// Through the wire and back, the same.
	data, err := json.Marshal(node)
	if err != nil {
		t.Fatal(err)
	}
	var decoded DependencyNode
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SourceScope != "optional" {
		t.Fatalf("SourceScope after the codec = %q, want preserved", decoded.SourceScope)
	}
	if got := CycloneDXScopeForExport(decoded.Scopes, decoded.SourceScope); got != string(cdx.ScopeOptional) {
		t.Fatalf("export after the codec = %q, want %q", got, cdx.ScopeOptional)
	}

	// Bomly's set changed -- propagation found it on a runtime path too --
	// so the set now says something the word did not, and the projection is
	// written instead.
	node.AddScope(ScopeRuntime)
	if got := CycloneDXScopeForExport(node.Scopes, node.SourceScope); got != string(cdx.ScopeRequired) {
		t.Fatalf("export after the set changed = %q, want the projection %q", got, cdx.ScopeRequired)
	}

	// "excluded" round-trips the same way, and the source's case is not the
	// document's: the library spelling is what gets written.
	if got := CycloneDXScopeForExport(ScopesFromCycloneDX("excluded"), "Excluded"); got != string(cdx.ScopeExcluded) {
		t.Fatalf("export = %q, want %q", got, cdx.ScopeExcluded)
	}

	// A source word outside the CycloneDX vocabulary never reaches a
	// CycloneDX document; the projection does. Nor does an empty one.
	for _, source := range []string{"compile", "", "   "} {
		if got := CycloneDXScopeForExport(ScopesOf(ScopeRuntime), source); got != string(cdx.ScopeRequired) {
			t.Errorf("source %q: export = %q, want the projection", source, got)
		}
	}
	// A set that says nothing writes no scope, whatever the source claimed:
	// the set changed from what the word derives to.
	if got := CycloneDXScopeForExport(nil, "optional"); got != "" {
		t.Errorf("export for an empty set = %q, want none", got)
	}
}

// A component that stated no scope is ingested at CycloneDX's default for an
// unspecified scope, so it exports as an explicit "required" rather than as
// nothing. That is a visible difference in the written document, and it is
// deliberate: the source asserted no word to re-emit, and "required" is what
// the specification says an unspecified scope means, so writing it states the
// reading Bomly actually applied instead of leaving the next consumer to
// re-derive it.
func TestAnUnscopedComponentExportsTheDefaultExplicitly(t *testing.T) {
	scopes := ScopesFromCycloneDX("")
	if got := CycloneDXScopeForExport(scopes, ""); got != string(cdx.ScopeRequired) {
		t.Errorf("export = %q, want the default written as %q", got, cdx.ScopeRequired)
	}
}

// The gate: a scope scalar is one token. It is applied on both wire
// directions and when a prototype is copied, so no call site can bypass it.
func TestSourceScopeIsGated(t *testing.T) {
	for _, bad := range []string{
		"", "  ", "with space", "tab\there", "line\nbreak", "\x7f", "bad\xffutf8",
		strings.Repeat("s", maxVocabularyTokenLength+1),
	} {
		if got := NormalizeSourceScope(bad); got != "" {
			t.Errorf("NormalizeSourceScope(%q) = %q, want refused", bad, got)
		}
	}
	for _, good := range []string{"optional", " excluded ", "Required", "compile", strings.Repeat("s", maxVocabularyTokenLength)} {
		if got := NormalizeSourceScope(good); got != strings.TrimSpace(good) {
			t.Errorf("NormalizeSourceScope(%q) = %q, want kept trimmed", good, got)
		}
	}

	// A hand-set unpublishable value never reaches the wire.
	node := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "left-pad", Version: "1.3.0"})
	node.SourceScope = "line\nbreak"
	data, err := json.Marshal(node)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "source_scope") {
		t.Fatalf("an ungated source scope was written: %s", data)
	}
	// Nor survives a decode.
	var decoded DependencyNode
	if err := json.Unmarshal([]byte(`{"id":"pkg:npm/left-pad@1.3.0","purl":"pkg:npm/left-pad@1.3.0","source_scope":"with space"}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SourceScope != "" {
		t.Fatalf("an ungated source scope survived decode: %q", decoded.SourceScope)
	}
	// The prototype constructor copies it through the gate too.
	from, err := NewDependencyNodeFrom(DependencyNode{
		Coordinates: Coordinates{Ecosystem: EcosystemNPM, Name: "left-pad", Version: "1.3.0"},
		SourceScope: " optional ",
	})
	if err != nil {
		t.Fatal(err)
	}
	if from.SourceScope != "optional" {
		t.Fatalf("NewDependencyNodeFrom SourceScope = %q, want the gated copy", from.SourceScope)
	}
}

// Merge class: scalar, fill-gaps. Two documents disagreeing about a
// component's scope is not resolved by picking one, so the first stated word
// stands; a witness that stated none contributes nothing, and one that stated
// something fills a gap.
func TestSourceScopeFillsGapsOnFold(t *testing.T) {
	g := New()
	first := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "left-pad", Version: "1.3.0"})
	first.SourceScope = "optional"
	if _, err := g.InsertNode(first); err != nil {
		t.Fatal(err)
	}
	second := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "left-pad", Version: "1.3.0"})
	second.SourceScope = "excluded"
	if _, err := g.InsertNode(second); err != nil {
		t.Fatal(err)
	}
	if first.SourceScope != "optional" {
		t.Fatalf("a stated source scope was overwritten: %q", first.SourceScope)
	}

	blank := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "is-odd", Version: "3.0.1"})
	if _, err := g.InsertNode(blank); err != nil {
		t.Fatal(err)
	}
	stated := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "is-odd", Version: "3.0.1"})
	stated.SourceScope = "required"
	if _, err := g.InsertNode(stated); err != nil {
		t.Fatal(err)
	}
	if blank.SourceScope != "required" {
		t.Fatalf("a gap was not filled: %q", blank.SourceScope)
	}

	// Gated on both sides before the gap is measured: an unpublishable
	// survivor value does not block a valid incoming one.
	dirty := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "chalk", Version: "5.0.0"})
	dirty.SourceScope = "with space"
	if _, err := g.InsertNode(dirty); err != nil {
		t.Fatal(err)
	}
	clean := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "chalk", Version: "5.0.0"})
	clean.SourceScope = "optional"
	if _, err := g.InsertNode(clean); err != nil {
		t.Fatal(err)
	}
	if dirty.SourceScope != "optional" {
		t.Fatalf("an ungated survivor blocked a valid witness: %q", dirty.SourceScope)
	}
}
