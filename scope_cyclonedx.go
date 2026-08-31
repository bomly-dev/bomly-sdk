package sdk

import (
	"fmt"
	"sort"
	"strings"

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

// DecodeScopeSet parses a carrier value written by EncodeScopeSet. It is
// strict: an unrecognized token is an error rather than a silently dropped
// scope, because this value is Bomly's own and a token it cannot read means
// the value did not come from where the caller thinks it did.
//
// The result is deduplicated and sorted, so decoding and re-encoding gives the
// same bytes.
func DecodeScopeSet(value string) ([]Scope, error) {
	if len(value) > maxScopeSetCarrierLength {
		return nil, fmt.Errorf("scope set is %d bytes, over the %d byte limit", len(value), maxScopeSetCarrierLength)
	}
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, nil
	}
	var scopes []Scope
	for _, field := range strings.Split(trimmed, ",") {
		// An empty field is malformed, not absent. ParseScope reads "" as
		// ScopeUnknown with no error -- correct for a detector that has
		// nothing to say, wrong here, where a separator with nothing after it
		// means the value is not what it claims to be. Skipping it would make
		// "runtime," decode as "runtime" and re-encode to different bytes.
		if strings.TrimSpace(field) == "" {
			return nil, fmt.Errorf("scope set %q has an empty entry", value)
		}
		scope, err := ParseScope(field)
		if err != nil {
			return nil, fmt.Errorf("scope set %q: %w", value, err)
		}
		if scope == ScopeUnknown {
			return nil, fmt.Errorf("scope set %q names an unknown scope", value)
		}
		if !containsScope(scopes, scope) {
			scopes = append(scopes, scope)
		}
	}
	sort.Slice(scopes, func(i, j int) bool { return scopes[i] < scopes[j] })
	return scopes, nil
}

// ScopesFromCycloneDXComponent reads a component's scopes, preferring the
// carrier property over the scalar scope.
//
// The precedence is the point of the pair. The carrier holds what Bomly
// recorded; the scalar holds a projection of it that cannot express a set. On
// a document Bomly wrote, both are present and only the carrier is exact. A
// carrier that fails to parse is treated as absent -- the scalar is still a
// true statement about the component, and dropping the scope entirely because
// the richer field was malformed would lose more than it protects.
func ScopesFromCycloneDXComponent(scope, carrier string) []Scope {
	if decoded, err := DecodeScopeSet(carrier); err == nil && len(decoded) > 0 {
		return decoded
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
