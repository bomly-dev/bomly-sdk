package purlkit

// identityQualifierKeys is the allowlist of qualifier keys that participate
// in package identity (ADR-0036 in bomly-cli's dev-docs/adr). Qualifiers
// enter the identity form of a package URL only through this table; every
// other qualifier is dropped, because qualifiers routinely carry resolution
// evidence (repository URLs, checksums, download locations) that must not
// become part of a published identity. The table is deliberately empty
// today: admitting the first key is an identity-spec version bump, ships
// the ADR-0033 credential and local-path gates for URL-valued qualifiers,
// and regenerates the identity golden vectors.
var identityQualifierKeys = map[string]struct{}{}

// IdentityQualifierKeys returns the identity-bearing qualifier keys, for
// introspection and guard tests. The slice is a copy.
func IdentityQualifierKeys() []string {
	keys := make([]string, 0, len(identityQualifierKeys))
	for key := range identityQualifierKeys {
		keys = append(keys, key)
	}
	return keys
}

// IdentityForm renders the identity form of a package URL: the canonical
// rendering with qualifiers filtered through the identity allowlist —
// currently all dropped — and the subpath preserved, since a subpath names
// which part of the package is meant rather than how it was resolved. It
// returns "" when the value does not parse. This is the package-identity
// facet rendering the root package's PackageIdentity wraps.
func IdentityForm(value string) string {
	parsed, err := Parse(value)
	if err != nil {
		return ""
	}
	kept := parsed.Qualifiers[:0:0]
	for _, qualifier := range parsed.Qualifiers {
		if _, ok := identityQualifierKeys[qualifier.Key]; ok {
			kept = append(kept, qualifier)
		}
	}
	parsed.Qualifiers = kept
	return parsed.String()
}
