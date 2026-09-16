package plugin

import (
	"testing"

	"google.golang.org/protobuf/types/known/wrapperspb"

	sdk "github.com/bomly-dev/bomly-sdk"
)

// wireV1DuplicateName repeats "copyright" on a dependency node, with different
// values. Under v1 decoding the last one wins for a scalar field, which is the
// behavior this fixture pins -- not because the behavior is good, but because
// it is the behavior old plugins were built against.
//
// The two values differ on purpose. Equal values would prove only that the
// payload is accepted, and a decoder that kept the *first* occurrence would
// pass while silently changing what an old plugin's payload means.
//
// It repeats copyright rather than an identity field, which took a mutation
// check to notice. A node's version is backfilled from its canonical package
// URL (ADR-0041), so a duplicated "version" member never reaches the decoded
// node at all: a payload saying "9.9.9" beside a purl saying 1.3.0 decodes to
// 1.3.0, and an assertion on version would hold no matter how duplicates
// resolved. Copyright is free text with no other source, so it is the last
// duplicate or nothing.
const wireV1DuplicateName = `{"graphs":{"entries":[{"graph":{"nodes":[` +
	`{"id":"pkg:npm/left-pad@1.3.0","purl":"pkg:npm/left-pad@1.3.0","name":"left-pad",` +
	`"version":"1.3.0","copyright":"Copyright first","copyright":"Copyright last"}]}}]}}`

// wireV1InvalidUTF8 carries a lone 0xff byte in a free-text field. Under v1
// decoding it becomes U+FFFD and the payload still decodes.
const wireV1InvalidUTF8 = "{\"graphs\":{\"entries\":[{\"graph\":{\"nodes\":[" +
	"{\"id\":\"pkg:npm/left-pad@1.3.0\",\"purl\":\"pkg:npm/left-pad@1.3.0\"," +
	"\"name\":\"left-pad\",\"version\":\"1.3.0\",\"copyright\":\"\xff\"}]}}]}}"

// wireV1TransportGraph decodes a payload the way the transport actually does:
// through unmarshalPayload, out of a BytesValue envelope, into the result type
// a detector plugin returns.
//
// Calling encoding/json directly here would have guarded nothing. Every plugin
// request and response is decoded by unmarshalBytes in serve.go, so a
// migration that touched only that helper would leave a direct-json test green
// while real plugin traffic began rejecting these payloads -- the exact
// regression this file exists to catch.
func wireV1TransportGraph(t *testing.T, payload string) *sdk.Graph {
	t.Helper()
	result, err := unmarshalPayload[sdk.DetectionResult](wrapperspb.Bytes([]byte(payload)))
	if err != nil {
		t.Fatalf("the plugin transport must keep decoding this payload: %v", err)
	}
	if result.Graphs == nil || len(result.Graphs.Entries) != 1 || result.Graphs.Entries[0].Graph == nil {
		t.Fatalf("payload decoded without its graph: %+v", result)
	}
	graph := result.Graphs.Entries[0].Graph
	if graph.Size() != 1 {
		t.Fatalf("size = %d, want the one node", graph.Size())
	}
	return graph
}

// The plugin wire keeps v1 decoding semantics, and these fixtures are what
// stop that from changing by accident.
//
// ADR-0039 moves untrusted-document parsing to encoding/json/v2, whose
// defaults reject duplicate object names and invalid UTF-8. That is the right
// posture for an SBOM a stranger produced. It is the wrong posture for this
// wire: enabled plugins are trusted native processes launched by the user, so
// the contract here is frozen fixtures and strict additivity, and tightening
// decoding is a protocol decision that needs its own ADR rather than a side
// effect of a parser migration in a consumer.
//
// The hazard being guarded is drift. Nobody sets out to tighten the plugin
// wire; someone swaps a decoder because it is the one they just used
// elsewhere, and a plugin built last year stops loading. If these fail,
// the change under review did exactly that.
//
// One deliberate exception already exists and is pinned separately by
// TestWireV1StrictDependencyIdentity: a dependency payload whose identity
// cannot mint a well-formed package URL fails decode (ADR-0041). That is
// tightening on purpose, ruled and fixture-backed -- which is precisely why
// accidental tightening needs its own guard rather than being assumed absent.
func TestWireV1KeepsLenientDecoding(t *testing.T) {
	t.Run("duplicate object name", func(t *testing.T) {
		node := wireV1TransportGraph(t, wireV1DuplicateName).DependencyNodes()[0]
		// The last occurrence, not merely "it decoded": a decoder that kept
		// the first would change what an old plugin's payload means, which is
		// a compatibility break wearing leniency's clothes.
		if node.Copyright != "Copyright last" {
			t.Fatalf("copyright = %q, want the last occurrence v1 keeps", node.Copyright)
		}
	})

	t.Run("invalid utf-8", func(t *testing.T) {
		node := wireV1TransportGraph(t, wireV1InvalidUTF8).DependencyNodes()[0]
		// The replacement is v1's own behavior, restated here so a change to
		// it is visible rather than silent.
		if node.Copyright != "\uFFFD" {
			t.Fatalf("copyright = %q, want the replacement character v1 substitutes", node.Copyright)
		}
	})
}
