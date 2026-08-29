package purlkit

import (
	"sort"
	"strings"
)

// evidenceQualifierKeys are the specification's universal URL-valued
// qualifier keys. Their values are resolution evidence — where a package was
// fetched or resolved from — which can embed signed links and credentials,
// so identity handling relocates them into the origin model (ADR-0033's
// constructors, which reject query-carrying artifact URLs outright) rather
// than letting them shape a published identity. Every other qualifier is
// identity: the specification's qualifier vocabulary is open — its per-type
// lists are documentation, not closed sets (the apk definition itself
// references a distro qualifier its own list omits) — and container purls
// legitimately carry arch/distro/upstream identity dimensions, so nothing
// beyond these three keys is filtered.
var evidenceQualifierKeys = map[string]struct{}{
	"repository_url": {},
	"download_url":   {},
	"vcs_url":        {},
}

// EvidenceQualifierKeys returns the specification's universal URL-valued
// evidence qualifier keys, sorted. The slice is a copy.
func EvidenceQualifierKeys() []string {
	keys := make([]string, 0, len(evidenceQualifierKeys))
	for key := range evidenceQualifierKeys {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// IsEvidenceQualifierKey reports whether the key is one of the universal
// URL-valued evidence qualifier keys. Keys compare case-insensitively, as
// the specification lowercases qualifier keys.
func IsEvidenceQualifierKey(key string) bool {
	_, ok := evidenceQualifierKeys[strings.ToLower(strings.TrimSpace(key))]
	return ok
}

// IdentitySplit partitions a package URL's qualifiers into the identity
// half and the evidence half.
type IdentitySplit struct {
	// Identity is the canonical package URL with only identity qualifiers —
	// everything except the universal evidence keys.
	Identity PURL
	// Evidence holds the relocated URL-valued evidence qualifiers, in
	// canonical qualifier order. Consumers pass their values through the
	// origin constructors; the raw values never reach a published ID.
	Evidence []Qualifier
}

// SplitIdentity partitions the qualifiers of a parsed package URL: the
// universal evidence keys move to Evidence, and everything else — spec-known
// and custom alike — stays on the identity, matching the specification's
// open qualifier vocabulary.
func SplitIdentity(p PURL) IdentitySplit {
	split := IdentitySplit{Identity: p}
	split.Identity.Qualifiers = nil
	for _, qualifier := range p.Qualifiers {
		// Classify case-insensitively: Parse lowercases keys, but PURL and
		// Qualifier are exported, so a hand-built value can carry
		// "DOWNLOAD_URL" — an exact lookup would let it bypass the evidence
		// partition and publish as an identity qualifier.
		if IsEvidenceQualifierKey(qualifier.Key) {
			split.Evidence = append(split.Evidence, qualifier)
			continue
		}
		split.Identity.Qualifiers = append(split.Identity.Qualifiers, qualifier)
	}
	return split
}

// IdentityForm renders the identity form of a package URL string: the
// canonical rendering with the universal evidence qualifiers removed and
// every other qualifier and the subpath preserved. It returns "" when the
// value does not parse.
func IdentityForm(value string) string {
	parsed, err := Parse(value)
	if err != nil {
		return ""
	}
	return SplitIdentity(parsed).Identity.String()
}
