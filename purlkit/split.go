package purlkit

import "strings"

// SplitEcosystemName splits an ecosystem-native package name back into its
// org and name halves — the inverse of the root Coordinates.EcosystemName
// join, under the same per-ecosystem rules (bomly-cli ADR-0021): joining is
// opt-in per ecosystem, so only ecosystems whose advisory databases key on
// the namespaced form split at all.
//
// The ecosystem argument accepts canonical tokens and their aliases (it is
// resolved through CanonicalEcosystem). For every ecosystem outside the join
// list the whole input is the name and org is empty — for OS packages the
// org is a distro, not part of the package name, and splitting would corrupt
// identity. A name that does not carry the ecosystem's join shape (an npm
// name without a scope, a Maven name without a colon) is likewise returned
// whole: absence of a namespace is data, not an error.
func SplitEcosystemName(ecosystem, ecosystemName string) (org, name string) {
	value := strings.TrimSpace(ecosystemName)
	if value == "" {
		return "", ""
	}
	canonical, ok := CanonicalEcosystem(ecosystem)
	if !ok {
		return "", value
	}
	switch canonical {
	case "npm":
		// "@scope/name" → ("scope", "name"). The scope marker is required:
		// a bare name has no org even when it contains a slash.
		if !strings.HasPrefix(value, "@") {
			return "", value
		}
		scope, rest, found := strings.Cut(value[1:], "/")
		if !found || scope == "" || rest == "" {
			return "", value
		}
		return scope, rest
	case "maven", "scala":
		// "group:artifact" → ("group", "artifact"), splitting at the first
		// colon: group IDs never contain colons, artifact IDs may not either
		// but the first-cut rule keeps the split total.
		group, artifact, found := strings.Cut(value, ":")
		if !found || group == "" || artifact == "" {
			return "", value
		}
		return group, artifact
	case "go", "php", "swift", "github-actions":
		// Path-style: everything before the last slash is the org, so
		// multi-segment Go module namespaces stay whole.
		before, after, found := strings.CutLast(value, "/")
		if !found || before == "" || after == "" {
			return "", value
		}
		return before, after
	default:
		return "", value
	}
}
