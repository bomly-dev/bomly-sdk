package sdk

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// A dependency's scope is a set here and a single value in CycloneDX. A
// package reachable from both a runtime root and a development root carries
// both scopes, and CycloneDX's component.scope holds one of "required",
// "optional", or "excluded".
//
// Projecting the set onto that scalar loses the set. So the projection is
// paired with a carrier property that keeps it, and ingest prefers the carrier
// when it is present. A Bomly document therefore round-trips exactly, while a
// document from any other producer still yields a usable set.
//
// The three scope spellings are cyclonedx-go's own constants. What is Bomly's
// here is only the policy -- which scope set projects onto which value -- and
// no library states that, because no library knows what Bomly's scopes mean.

// CycloneDXScopeProperty is the property name carrying the full scope set
// through a CycloneDX document, so the projection below is not a one-way door.
//
// The "bomly:" prefix follows the CycloneDX guidance that property names be
// namespaced by their producer, which is what keeps this from colliding with
// another tool's property of the same purpose.
const CycloneDXScopeProperty = "bomly:scopes"

// maxScopeSetCarrierLength bounds a carrier value read from a document. A real
// set is two short tokens; this leaves room for growth without admitting a
// value that is really a payload.
const maxScopeSetCarrierLength = 256

// CycloneDXScope projects a scope set onto CycloneDX's scalar component scope.
// It returns "" when the set says nothing, which a caller writes as no scope
// at all rather than as a guess.
//
// The rule is that a package reachable at runtime is required, and a package
// reachable only from development roots is excluded -- CycloneDX's word for a
// component that is present in the source tree but not in what ships. Runtime
// wins over development in a mixed set for the same reason MergeScope prefers
// it: a package reachable at runtime ships, whatever else is also true of it.
//
// "optional" is never produced. It means "provides additional functionality",
// a distinction Bomly's scope vocabulary does not draw, and inventing it here
// would put a claim in a document that no detector made.
func CycloneDXScope(scopes []Scope) string {
	found := false
	for _, scope := range scopes {
		switch scope {
		case ScopeRuntime:
			return string(cdx.ScopeRequired)
		case ScopeDevelopment:
			found = true
		}
	}
	if found {
		return string(cdx.ScopeExcluded)
	}
	return ""
}

// ScopesFromCycloneDX derives a scope set from CycloneDX's scalar scope, for a
// document Bomly did not write. It returns nil when the value says nothing,
// which is also what an unrecognized value gives: a scope Bomly cannot read is
// not a scope it should guess at.
//
// "optional" reads as runtime. An optional component provides additional
// functionality at runtime -- it is not a development-only dependency -- so
// required and optional both land on runtime. That is lossy in the direction
// that matters least, and it is why CycloneDXScopeProperty exists.
func ScopesFromCycloneDX(value string) []Scope {
	switch cdx.Scope(strings.ToLower(strings.TrimSpace(value))) {
	case cdx.ScopeRequired, cdx.ScopeOptional:
		return []Scope{ScopeRuntime}
	case cdx.ScopeExcluded:
		return []Scope{ScopeDevelopment}
	default:
		return nil
	}
}

// EncodeScopeSet renders a scope set as a carrier value: the canonical scope
// tokens, sorted and comma-separated. It returns "" when there is nothing to
// carry, which a caller writes as no property at all.
//
// Sorted because a document is built from this, and two runs that found the
// same scopes in a different order must produce the same bytes.
func EncodeScopeSet(scopes []Scope) string {
	tokens := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if scope == ScopeUnknown {
			continue
		}
		token := string(scope)
		if !containsString(tokens, token) {
			tokens = append(tokens, token)
		}
	}
	if len(tokens) == 0 {
		return ""
	}
	sort.Strings(tokens)
	return strings.Join(tokens, ",")
}

// ScopeSetDecoding is what a carrier value said, read leniently: the scopes
// it named that this build knows, and the tokens it named that it does not.
//
// Unknown is the warning channel. The SDK does not log, and a token it cannot
// read is worth telling a user about -- it is most likely a scope a newer
// Bomly wrote -- so the caller gets the tokens and decides how to say so.
type ScopeSetDecoding struct {
	// Scopes are the recognized scopes, deduplicated and sorted, so
	// re-encoding them gives stable bytes.
	Scopes []Scope
	// Unknown are the tokens this build does not recognize, lowercased the
	// way ParseScope reads a token, in the order written, deduplicated.
	// Empty when every token was read. Each has the shape of a scope token
	// -- see isScopeTokenShaped -- because anything else is not a scope a
	// newer build might have written; it is a malformed carrier, and that
	// is an error rather than an entry here.
	Unknown []string
}

// isScopeTokenShaped reports whether a token this build does not know still
// has the shape of a scope token, so that it can be one a newer build wrote,
// rather than structure a carrier would never contain. The shape is the one
// Bomly's own vocabulary tokens have -- "runtime", "development", and every
// token in the model's other closed vocabularies: lowercase ASCII letters,
// digits, hyphen, underscore, within the vocabulary token bound. This is
// Bomly's own vocabulary, so no library owns the shape; a token that fails
// it -- a space, a control character, invalid UTF-8, a run past the bound --
// is not a future scope but a value that did not come from a carrier.
func isScopeTokenShaped(token string) bool {
	if token == "" || len(token) > maxVocabularyTokenLength {
		return false
	}
	for _, r := range token {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// DecodeScopeSetLenient reads a carrier value the way ADR-0037 states: the
// scopes it names that this build knows are kept, and the tokens it does not
// know are dropped and reported rather than failing the whole value.
//
// The strict reading used to be the only one, and it was a forward
// compatibility trap: a newer Bomly writing one scope token an older one
// does not know made the older one lose the whole assertion, so a component
// the document scoped "runtime,future" became unscoped and a runtime filter
// dropped it. CycloneDX ingest could fall back to the scalar scope; SPDX has
// no scalar, so the loss there was total. The token an old build cannot read
// is still evidence -- it comes back in Unknown -- but the tokens it can read
// are still true, and those are kept.
//
// What is still an error is a value that is not a carrier at all: over the
// byte bound, with an empty entry (a separator with nothing after it), or
// with an entry that is not shaped like a scope token at all -- a space, a
// control character, invalid UTF-8. A carrier is Bomly's own, and structure
// it would never write means the value did not come from where the caller
// thinks it did; treating such an entry as a future scope would let a
// malformed carrier override a valid scalar scope and surface garbage
// through the warning channel.
func DecodeScopeSetLenient(value string) (ScopeSetDecoding, error) {
	if len(value) > maxScopeSetCarrierLength {
		return ScopeSetDecoding{}, fmt.Errorf("scope set is %d bytes, over the %d byte limit", len(value), maxScopeSetCarrierLength)
	}
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ScopeSetDecoding{}, nil
	}
	var decoded ScopeSetDecoding
	for _, field := range strings.Split(trimmed, ",") {
		// An empty field is malformed, not absent. ParseScope reads "" as
		// ScopeUnknown with no error -- correct for a detector that has
		// nothing to say, wrong here, where a separator with nothing after it
		// means the value is not what it claims to be. Skipping it would make
		// "runtime," decode as "runtime" and re-encode to different bytes.
		token := strings.TrimSpace(field)
		if token == "" {
			return ScopeSetDecoding{}, fmt.Errorf("scope set %q has an empty entry", value)
		}
		scope, err := ParseScope(token)
		if err != nil || scope == ScopeUnknown {
			lowered := strings.ToLower(token)
			if !isScopeTokenShaped(lowered) {
				return ScopeSetDecoding{}, fmt.Errorf("scope set %q has a malformed entry %q", value, token)
			}
			if !containsString(decoded.Unknown, lowered) {
				decoded.Unknown = append(decoded.Unknown, lowered)
			}
			continue
		}
		if !containsScope(decoded.Scopes, scope) {
			decoded.Scopes = append(decoded.Scopes, scope)
		}
	}
	sort.Slice(decoded.Scopes, func(i, j int) bool { return decoded.Scopes[i] < decoded.Scopes[j] })
	return decoded, nil
}

// DecodeScopeSet parses a carrier value written by EncodeScopeSet, strictly:
// an unrecognized token is an error, and nothing is returned beside it. It is
// the lenient reading with one more rule, for a caller that must know the
// value was written by a build that knows every token in it -- verifying a
// document Bomly itself wrote, for one. Ingest of a document from anywhere
// uses DecodeScopeSetLenient, because there the tokens an old build can read
// are still true and dropping them loses a scope the document stated.
//
// The result is deduplicated and sorted, so decoding and re-encoding gives the
// same bytes.
func DecodeScopeSet(value string) ([]Scope, error) {
	decoded, err := DecodeScopeSetLenient(value)
	if err != nil {
		return nil, err
	}
	if len(decoded.Unknown) > 0 {
		return nil, fmt.Errorf("scope set %q names an unknown scope %q", value, decoded.Unknown[0])
	}
	return decoded.Scopes, nil
}

// NormalizeSourceScope is the gate for DependencyNode.SourceScope: the scope
// word a source document used, kept in that document's vocabulary. A scope
// scalar is a single token in every format that has one, so the value is
// trimmed and refused when it is empty, longer than a vocabulary token, not
// valid UTF-8, or carries a control or whitespace character -- any of which
// means it was not a scope a document stated. It is not lowercased: what is
// preserved is the claim as written, and the export helper below applies the
// target format's spelling when it re-emits it.
func NormalizeSourceScope(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || len(trimmed) > maxVocabularyTokenLength || !utf8.ValidString(trimmed) {
		return ""
	}
	for _, r := range trimmed {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return ""
		}
	}
	return trimmed
}

// CycloneDXScopeForExport returns the scalar scope a CycloneDX export writes
// for a component: the source document's own word when Bomly's scope set
// still means what that word meant, and Bomly's projection of the set
// otherwise.
//
// ADR-0037 asks that an ingested scope scalar be re-emitted verbatim unless
// Bomly's own scope set changed, so "optional" and "excluded" never collapse
// across a round trip that asserted neither. "Still means the same" is
// decided by the same rule that read the word in: the set ScopesFromCycloneDX
// derives from it must equal the set the node carries now. A node ingested
// as "optional" carries {runtime} and re-exports as "optional"; once
// propagation adds development to it, the set says something the word did
// not, and the projection ("required") is written instead. A source word
// outside the CycloneDX vocabulary -- another format's, or nothing -- never
// reaches a CycloneDX document; the projection does.
//
// The result is always "" or one of cyclonedx-go's three scope spellings, in
// the library's case, whatever case the source wrote.
func CycloneDXScopeForExport(scopes []Scope, sourceScope string) string {
	projected := CycloneDXScope(scopes)
	source := NormalizeSourceScope(sourceScope)
	if source == "" {
		return projected
	}
	derived := ScopesFromCycloneDX(source)
	if derived == nil || EncodeScopeSet(derived) != EncodeScopeSet(scopes) {
		return projected
	}
	return string(cdx.Scope(strings.ToLower(source)))
}

// ScopesFromCycloneDXComponent reads a component's scopes, preferring the
// carrier property over the scalar scope.
//
// The precedence is the point of the pair. The carrier holds what Bomly
// recorded; the scalar holds a projection of it that cannot express a set. On
// a document Bomly wrote, both are present and only the carrier is exact. The
// carrier is read leniently: the scopes this build knows are kept even when
// a token beside them is not, since a newer Bomly's token is not a reason to
// discard the scopes an older one can still read. A carrier that is malformed
// outright, or names nothing this build knows, is treated as absent -- the
// scalar is still a true statement about the component, and dropping the
// scope entirely because the richer field was unreadable would lose more
// than it protects. A caller that wants to surface the unknown tokens reads
// the carrier with DecodeScopeSetLenient itself.
func ScopesFromCycloneDXComponent(scope, carrier string) []Scope {
	if decoded, err := DecodeScopeSetLenient(carrier); err == nil && len(decoded.Scopes) > 0 {
		return decoded.Scopes
	}
	return ScopesFromCycloneDX(scope)
}

// containsScope reports whether a scope is already in a set.
func containsScope(scopes []Scope, scope Scope) bool {
	for _, existing := range scopes {
		if existing == scope {
			return true
		}
	}
	return false
}

// containsString reports whether a token is already in a slice.
func containsString(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}
	return false
}
