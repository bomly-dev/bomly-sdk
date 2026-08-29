package sdk

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-sdk/purlkit"
)

// Scope describes the normalized dependency scope surfaced to users.
type Scope string

const (
	// ScopeUnknown indicates that a detector could not determine dependency scope.
	ScopeUnknown Scope = ""
	// ScopeRuntime indicates a dependency required at runtime.
	ScopeRuntime Scope = "runtime"
	// ScopeDevelopment indicates a dependency used only for development workflows.
	ScopeDevelopment Scope = "development"
)

// ParseScope normalizes a user-provided dependency scope value.
func ParseScope(value string) (Scope, error) {
	switch Scope(strings.ToLower(strings.TrimSpace(value))) {
	case ScopeRuntime:
		return ScopeRuntime, nil
	case ScopeDevelopment:
		return ScopeDevelopment, nil
	case ScopeUnknown:
		return ScopeUnknown, nil
	default:
		return ScopeUnknown, fmt.Errorf("unsupported scope %q", value)
	}
}

// MergeScope combines two normalized scopes, preferring runtime when a package
// is reachable from both runtime and development roots.
func MergeScope(current, next Scope) Scope {
	switch {
	case next == ScopeUnknown:
		return current
	case current == ScopeUnknown:
		return next
	case current == ScopeRuntime || next == ScopeRuntime:
		return ScopeRuntime
	default:
		return ScopeDevelopment
	}
}

// DependencyQuery identifies a specific component target.
type DependencyQuery struct {
	Name string `json:"name,omitempty"`
	ID   string `json:"id,omitempty"`
}

// ScopesOf returns a deduplicated scope slice without unknown entries, or nil.
// Convenience for detectors building node scopes from parsed groups.
func ScopesOf(scopes ...Scope) []Scope {
	out := make([]Scope, 0, len(scopes))
	for _, s := range scopes {
		if s == ScopeUnknown {
			continue
		}
		dup := false
		for _, existing := range out {
			if existing == s {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// DependencyNode is the union's third-party package record: one resolved
// dependency, the unit of matching and enrichment (ADR-0041). Its identity
// — and therefore its published graph ID — is its canonical package URL,
// minted only by the constructors below; there is no ID override, no
// occurrence suffix, and no identity outside the PURL. Matching enrichment
// (licenses, vulnerabilities, scorecard) lives on the referenced Package,
// not here.
type DependencyNode struct {
	Coordinates
	Relationship DependencyRelationship
	Source       DependencySource
	Scopes       []Scope
	Locations    []PackageLocation
	CPEs         []string
	Digests      []Digest
	Copyright    string
	FoundBy      string
	// ResolvedURL is the manifest's resolution field verbatim — it may be a
	// pseudo-URL, a registry or index root, or a local path, and is never
	// published. It is raw evidence; Origins carry the validated assertions.
	ResolvedURL string
	// Origins is where this dependency was resolved from: metadata, never
	// identity (ADR-0041). Union-merged and deduplicated by normalized
	// value; the ADR-0033 publication gates are the only door in. A list
	// with more than one element is an observable fact — the shape of a
	// dependency-confusion signal — not a reason to split the node.
	Origins  []DependencyOrigin
	Metadata map[string]any
	// Matched is true when the referenced package was enriched by a matcher.
	Matched bool
	// PackageRef is the PURL of this dependency's matching artifact. It is
	// derived — seeding sets it to NodeID(), which is the same canonical
	// PURL — and retained for wire compatibility with older readers.
	PackageRef string

	id       string
	purl     purlkit.PURL
	warnings []NodeWarning
}

// dependencyIdentity is the parsed outcome of the identity gate.
type dependencyIdentity struct {
	rendered       string
	parsed         purlkit.PURL
	missingVersion bool
}

// dependencyIdentityFromPURL runs the identity gate on a raw package URL:
// parse (library syntax + canonical form), split the universal evidence
// qualifiers off the identity, and validate the identity against its type's
// specification profile. Unknown purl types pass on syntax alone — the type
// vocabulary is open, and a custom ecosystem's own type is first-class.
func dependencyIdentityFromPURL(raw string) (dependencyIdentity, []purlkit.Qualifier, error) {
	parsed, err := purlkit.Parse(raw)
	if err != nil {
		return dependencyIdentity{}, nil, err
	}
	split := purlkit.SplitIdentity(parsed)
	if err := purlkit.Validate(split.Identity); err != nil {
		return dependencyIdentity{}, nil, err
	}
	rendered := split.Identity.String()
	if rendered == "" {
		return dependencyIdentity{}, nil, fmt.Errorf("package URL identity does not render")
	}
	return dependencyIdentity{
		rendered:       rendered,
		parsed:         split.Identity,
		missingVersion: split.Identity.Version == "",
	}, split.Evidence, nil
}

// NewDependencyNode constructs a dependency node from coordinates: the
// fields are normalized (per-ecosystem case, separator, and format rules —
// the same pass NormalizeCoordinates exposes), the canonical package URL is
// minted, and the identity is validated against the purl specification. A
// node that cannot mint a valid package URL is an error, not a silently
// empty ID; a missing version is a recorded warning, because the
// specification leaves version optional and first-party-adjacent records
// legitimately lack one.
func NewDependencyNode(coords Coordinates) (*DependencyNode, error) {
	return newDependencyNode(coords, "")
}

// NewDependencyNodeFromPURL constructs a dependency node from a raw package
// URL — the qualifier-capable path. The URL-valued evidence qualifiers
// (repository_url, download_url, vcs_url) are relocated through the
// ADR-0033 origin constructors into Origins — a value the gates reject (a
// signed or tokenized link) is discarded entirely with a recorded warning,
// never sanitized into something publishable — and every other qualifier
// stays on the identity. Coordinates are back-filled from the parsed
// identity.
func NewDependencyNodeFromPURL(rawPURL string) (*DependencyNode, error) {
	return newDependencyNode(Coordinates{PURL: rawPURL}, rawPURL)
}

func newDependencyNode(coords Coordinates, rawPURL string) (*DependencyNode, error) {
	scratch := coords
	normalizeCoordinateVocabulary(&scratch)
	applied := NormalizeCoordinates(&scratch)

	minted := strings.TrimSpace(rawPURL)
	if minted == "" {
		minted = scratch.CanonicalPURL()
	}
	if minted == "" {
		return nil, fmt.Errorf("dependency node: no package URL is derivable from %q", coords.QualifiedName())
	}
	identity, evidence, err := dependencyIdentityFromPURL(minted)
	if err != nil {
		return nil, fmt.Errorf("dependency node: %w", err)
	}

	node := &DependencyNode{Coordinates: scratch, id: identity.rendered, purl: identity.parsed}
	node.Coordinates.PURL = identity.rendered
	node.backfillCoordinates()
	if identity.missingVersion {
		node.warnings = append(node.warnings, NodeWarning{
			Code:    NodeWarningMissingVersion,
			Message: "package URL carries no version",
		})
	}
	node.adoptEvidenceQualifiers(evidence)
	node.recordNormalization(coords, applied)
	return node, nil
}

// backfillCoordinates fills coordinate fields the identity implies when the
// caller left them empty, so a node constructed from a bare package URL
// still presents ecosystem-native names.
func (n *DependencyNode) backfillCoordinates() {
	if n.Name == "" {
		n.Name = n.purl.Name
	}
	if n.Org == "" && n.purl.Namespace != "" {
		n.Org = strings.TrimPrefix(n.purl.Namespace, "@")
	}
	if n.Version == "" {
		n.Version = n.purl.Version
	}
	if n.Ecosystem == "" {
		if ecosystem, ok := purlkit.EcosystemForType(n.purl.Type); ok {
			n.Ecosystem = Ecosystem(ecosystem)
		}
	}
	// Backfilled values pass the same normalization rules caller-supplied
	// ones already passed, so decoding a node from a bare package URL and
	// re-decoding that node's own wire form produce field-for-field
	// identical records. This is derivation, not caller-value
	// normalization, so nothing here lands in the provenance breadcrumbs;
	// the minted identity stays untouched.
	purl := n.Coordinates.PURL
	NormalizeCoordinates(&n.Coordinates)
	n.Coordinates.PURL = purl
}

// adoptEvidenceQualifiers relocates the URL-valued evidence qualifiers into
// Origins through the ADR-0033 constructors. Rejected values are discarded
// with a warning: identity handling never sanitizes a link into something
// publishable.
func (n *DependencyNode) adoptEvidenceQualifiers(evidence []purlkit.Qualifier) {
	for _, qualifier := range evidence {
		var origin *DependencyOrigin
		switch qualifier.Key {
		case "download_url":
			origin = ArtifactOrigin(qualifier.Value)
		case "repository_url", "vcs_url":
			url, revision := splitVCSLocator(qualifier.Value)
			origin = RepositoryOrigin(url, revision)
		}
		if origin == nil {
			n.warnings = append(n.warnings, NodeWarning{
				Code:    NodeWarningDroppedEvidenceQualifier,
				Message: fmt.Sprintf("%s qualifier did not survive the origin gates and was discarded", qualifier.Key),
			})
			continue
		}
		n.Origins = MergeOrigins(n.Origins, []DependencyOrigin{*origin})
	}
}

// splitVCSLocator decomposes the common "vcs+scheme://host/path@revision"
// qualifier form into its URL and revision halves. The leading vcs marker
// (git+, hg+, …) is dropped, and a trailing @revision after the authority is
// split off; the ADR-0033 gates then judge what remains.
func splitVCSLocator(value string) (string, string) {
	trimmed := strings.TrimSpace(value)
	if plus := strings.Index(trimmed, "+"); plus >= 0 && strings.Contains(trimmed[plus+1:], "://") {
		trimmed = trimmed[plus+1:]
	}
	schemeEnd := strings.Index(trimmed, "://")
	if schemeEnd < 0 {
		return trimmed, ""
	}
	if at := strings.LastIndex(trimmed, "@"); at > schemeEnd+3 {
		return trimmed[:at], trimmed[at+1:]
	}
	return trimmed, ""
}

// recordNormalization stores the applied-normalization breadcrumbs the old
// in-place pass recorded, so provenance stays inspectable.
func (n *DependencyNode) recordNormalization(original Coordinates, applied []string) {
	if len(applied) == 0 {
		return
	}
	if n.Metadata == nil {
		n.Metadata = make(map[string]any, 4)
	}
	n.Metadata[normMetadataAppliedKey] = normUniqueStrings(applied)
	if n.Name != original.Name && original.Name != "" {
		n.Metadata[normMetadataOriginalNameKey] = original.Name
	}
	if n.Org != original.Org && original.Org != "" {
		n.Metadata[normMetadataOriginalOrgKey] = original.Org
	}
	if n.Version != original.Version && original.Version != "" {
		n.Metadata[normMetadataOriginalVersionKey] = original.Version
	}
}

// NodeID returns the canonical package URL: the node's identity and its
// published graph ID are the same string.
func (n *DependencyNode) NodeID() string { return n.id }

// Kind returns NodeKindDependency.
func (n *DependencyNode) Kind() NodeKind { return NodeKindDependency }

// PURL returns a copy of the parsed canonical identity.
func (n *DependencyNode) PURL() purlkit.PURL { return n.purl }

// NodeLocations returns the dependency's witnessed locations.
func (n *DependencyNode) NodeLocations() []PackageLocation { return n.Locations }

// NodeWarnings returns the constructor-recorded recoverable conditions.
func (n *DependencyNode) NodeWarnings() []NodeWarning {
	return append([]NodeWarning(nil), n.warnings...)
}

// QualifiedName returns the name prefixed with its organization when present.
func (n *DependencyNode) QualifiedName() string {
	if n == nil {
		return ""
	}
	return n.Coordinates.QualifiedName()
}

// DisplayName returns the most human-friendly identifier available, using
// the ecosystem-native name form (e.g. "@org/name" for npm).
func (n *DependencyNode) DisplayName() string {
	if n == nil {
		return ""
	}
	if name := n.Coordinates.DisplayName(); name != "" {
		return name
	}
	return n.id
}

// PrimaryScope returns the merged precedence scope across all recorded scopes.
func (n *DependencyNode) PrimaryScope() Scope {
	if n == nil {
		return ScopeUnknown
	}
	result := ScopeUnknown
	for _, scope := range n.Scopes {
		result = MergeScope(result, scope)
	}
	return result
}

// HasScope reports whether the dependency carries the given scope.
func (n *DependencyNode) HasScope(scope Scope) bool {
	if n == nil {
		return false
	}
	for _, s := range n.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// AddScope records a scope on the dependency if not already present.
func (n *DependencyNode) AddScope(scope Scope) {
	if n == nil || scope == ScopeUnknown || n.HasScope(scope) {
		return
	}
	n.Scopes = append(n.Scopes, scope)
	sort.Slice(n.Scopes, func(i, j int) bool { return n.Scopes[i] < n.Scopes[j] })
}

// Clone returns a deep copy of the dependency node.
func (n *DependencyNode) Clone() *DependencyNode {
	if n == nil {
		return nil
	}
	clone := *n
	if len(n.Scopes) > 0 {
		clone.Scopes = append([]Scope(nil), n.Scopes...)
	}
	clone.CPEs = cloneStrings(n.CPEs)
	if len(n.Digests) > 0 {
		clone.Digests = append([]Digest(nil), n.Digests...)
	}
	clone.Locations = clonePackageLocations(n.Locations)
	if len(n.Origins) > 0 {
		clone.Origins = append([]DependencyOrigin(nil), n.Origins...)
	}
	clone.Metadata = cloneAnyMap(n.Metadata)
	clone.warnings = append([]NodeWarning(nil), n.warnings...)
	if len(n.purl.Qualifiers) > 0 {
		clone.purl.Qualifiers = append([]purlkit.Qualifier(nil), n.purl.Qualifiers...)
	}
	return &clone
}

// CloneNode implements GraphNode.
func (n *DependencyNode) CloneNode() GraphNode { return n.Clone() }

func (n *DependencyNode) sealedGraphNode() {}
