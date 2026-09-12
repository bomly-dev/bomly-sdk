package sdk

import (
	"encoding/json"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

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
		Ecosystem: EcosystemNPM, Name: "left-pad", Version: "1.3.0",
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
