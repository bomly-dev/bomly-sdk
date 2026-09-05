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
	Origins []DependencyOrigin
	// Licenses are the license claims the detecting or ingesting source made
	// about this dependency. Detection-time facts belong on the node;
	// consolidation lifts them into the registry package. This is the typed
	// replacement for the MetadataKeyDetectionLicenses stash.
	//
	// Gate: PackageLicense.Normalized. Merge class: set, unioned by
	// MergeLicenses -- a declaration and a conclusion are two claims about
	// one package, and two sources reusing one license reference for
	// different terms are kept apart.
	Licenses []PackageLicense
	// Description, Homepage, Supplier, and Originator are the component-level
	// SBOM assertions a source document made about this dependency
	// (ADR-0037). They live on the node as well as on Package because an
	// ingested document asserts them per component, before matching has
	// produced a registry package to hold them.
	//
	// Gates, applied on both wire directions and again when a node seeds a
	// registry package: NormalizeDescription (trimmed, bounded, control
	// characters dropped), NormalizeHomepage (URLFormReference, so a bare
	// host and a query are fine while credentials and local paths are
	// cleared), and Contact.Normalized for both contacts, which yields nil
	// for an unpublishable party and never retains an email address.
	//
	// Merge class for all four: scalar, fill-gaps. Both witnesses are gated
	// before the gap is measured, so a value that could not be published
	// never blocks one that can.
	Description string
	Homepage    string
	Supplier    *Contact
	Originator  *Contact
	// ExternalReferences are the references the source document attached to
	// this component. Gate: ExternalReference.Normalized, on both wire
	// directions and again when a node seeds a registry package. Merge class:
	// set, unioned by the (category, type, locator) triple.
	ExternalReferences []ExternalReference
	Metadata           map[string]any
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
	// Cache the parse of the rendered identity rather than the pre-render
	// struct: rendering applies the library's canonical form (trimming a
	// version's surrounding whitespace, for one), so the pre-render fields
	// can disagree with the ID they produced. Coordinates project from this
	// cache, and they must say exactly what the identity says.
	canonical, err := purlkit.Parse(rendered)
	if err != nil {
		return dependencyIdentity{}, nil, err
	}
	return dependencyIdentity{
		rendered:       rendered,
		parsed:         canonical,
		missingVersion: canonical.Version == "",
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

// NewDependencyNodeFrom constructs a dependency node from a prototype: the
// identity is minted from the prototype's coordinates, and every other field
// it states is copied onto the result.
//
// A node's identity is fixed at construction, so a producer that used to
// describe a package as one struct literal now has to construct first and
// assign after. Doing that by hand at each site is how a detector silently
// stops recording what it detected -- four npm-family lockfile parsers lost
// ResolvedURL and their integrity digests exactly that way, in one release,
// each for the same reason, and only a fixture assertion noticed.
//
// The field list lives here because this type owns it: a field added to the
// model is copied by every producer at once, rather than in as many places as
// remembered.
func NewDependencyNodeFrom(proto DependencyNode) (*DependencyNode, error) {
	node, err := NewDependencyNode(proto.Coordinates)
	if err != nil {
		return nil, err
	}
	node.Relationship = proto.Relationship
	node.Source = proto.Source
	node.Scopes = append([]Scope(nil), proto.Scopes...)
	// Through the shared helper, not a slice append: a location holds a
	// Position pointer and a Scopes slice, and copying only the outer slice
	// left both aliasing the prototype.
	node.Locations = clonePackageLocations(proto.Locations)
	node.CPEs = append([]string(nil), proto.CPEs...)
	node.Digests = append([]Digest(nil), proto.Digests...)
	node.Copyright = proto.Copyright
	node.FoundBy = proto.FoundBy
	node.ResolvedURL = proto.ResolvedURL
	// Merged onto what the constructor produced, not over it. Constructing
	// from coordinates relocates the URL-valued evidence qualifiers into
	// Origins (ADR-0033), and replacing the result with the prototype's list
	// discarded a repository the identity itself carried.
	node.Origins = MergeOrigins(node.Origins, proto.Origins)
	node.Licenses = MergeLicenses(nil, proto.Licenses)
	node.Description = proto.Description
	node.Homepage = proto.Homepage
	// Cloned, not aliased, like Clone does: a producer that reuses a
	// prototype across packages -- which is the whole reason this takes one
	// -- would otherwise mutate nodes it already built.
	node.Supplier = proto.Supplier.Clone()
	node.Originator = proto.Originator.Clone()
	node.ExternalReferences = MergeExternalReferences(nil, proto.ExternalReferences)
	// Same for metadata: normalization records its provenance breadcrumbs
	// under the reserved prefix, and overwriting the map lost them. A
	// prototype key wins for anything else, so a producer's own metadata
	// still lands; a reserved key does not, because that namespace is this
	// project's and the constructor is the one writing it.
	node.Metadata = mergeMetadataPreservingReserved(node.Metadata, proto.Metadata)
	node.Matched = proto.Matched
	// PackageRef is derived, not carried: it names the package this node
	// matched, which is the package its identity encodes. Copying a
	// prototype's value lets the two disagree, and a node whose PackageRef
	// points at a different package is enriched from the wrong entry.
	node.PackageRef = node.NodeID()
	return node, nil
}

func newDependencyNode(coords Coordinates, rawPURL string) (*DependencyNode, error) {
	scratch := coords
	normalizeCoordinateVocabulary(&scratch)
	applied := NormalizeCoordinates(&scratch)

	minted := strings.TrimSpace(rawPURL)
	if minted == "" {
		// A package URL on the coordinates is an assertion, not a hint:
		// honored or refused, never quietly replaced by one the coordinate
		// builder fabricates. Only coordinates that assert no package URL
		// mint one from their parts.
		minted = strings.TrimSpace(coords.PURL)
	}
	if minted == "" {
		minted = scratch.CanonicalPURL()
	}
	// A stated package URL is an assertion: honored or refused, never quietly
	// replaced by a looser one the caller did not write. Only coordinates
	// that assert none may fall back.
	stated := strings.TrimSpace(coords.PURL) != "" || strings.TrimSpace(rawPURL) != ""

	var (
		identity dependencyIdentity
		evidence []purlkit.Qualifier
		err      error
	)
	if minted != "" {
		identity, evidence, err = dependencyIdentityFromPURL(minted)
	} else {
		err = fmt.Errorf("no package URL is derivable from %q", coords.QualifiedName())
	}
	if err != nil && !stated {
		// The ecosystem's own package URL type could not express these
		// coordinates. Some type profiles require more than a resolver gives:
		// a SwiftPM registry pin names a package by identity alone and the
		// swift type requires a namespace; a bare Go module name has none
		// either. Fall back to a generic identity rather than refusing a
		// package that is genuinely installed -- and record that it happened,
		// so the looseness is observable rather than silent.
		//
		// Both failure shapes reach here. A type whose profile rejects the
		// parts outright mints nothing; one that mints a string the profile
		// then refuses fails the parse above. Handling only the first left a
		// bare Go module erroring where a bare Swift package fell back.
		if fallback := scratch.GenericPURL(); fallback != "" {
			if fallbackIdentity, fallbackEvidence, fallbackErr := dependencyIdentityFromPURL(fallback); fallbackErr == nil {
				identity, evidence, err = fallbackIdentity, fallbackEvidence, nil
			}
		}
	}
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
	if failedType, ok := genericFallbackType(identity.parsed); ok {
		// Derived from the identity, not tracked through construction, so a
		// node that crossed the wire carries it too. Warnings are
		// deliberately not serialized, and a decoded fallback arrives as a
		// stated pkg:generic URL that nothing would otherwise mark -- leaving
		// the consumer unable to tell a degraded identity from a package that
		// is genuinely generic, which is the whole signal.
		node.warnings = append(node.warnings, NodeWarning{
			Code: NodeWarningGenericIdentity,
			Message: fmt.Sprintf("package URL type %q cannot express these coordinates; identity minted as pkg:generic",
				failedType),
		})
	}
	node.adoptEvidenceQualifiers(evidence)
	// Provenance breadcrumbs describe how caller coordinates were shaped on
	// the way to the identity, so they are recorded only when coordinates
	// actually minted it — neither a raw package URL nor one asserted on
	// the coordinates. With either, the normalization pass touched nothing
	// that reached this node (its fields project from the identity), so
	// recording rules that changed nothing observable would mislead, let
	// irrelevant caller fields alter a node's metadata, and break codec
	// idempotence — a decoded node always carries the package URL its
	// predecessor emitted.
	if strings.TrimSpace(rawPURL) == "" && strings.TrimSpace(coords.PURL) == "" {
		node.recordNormalization(coords, applied)
	}
	return node, nil
}

// backfillCoordinates fills coordinate fields the identity implies when the
// caller left them empty, so a node constructed from a bare package URL
// still presents ecosystem-native names.
func (n *DependencyNode) backfillCoordinates() {
	// The identity decides the package family too: a record keyed
	// pkg:npm/foo@1 that claims ecosystem "maven" would seed its registry
	// package into the wrong family and take the wrong ecosystem-specific
	// name handling. A custom purl type resolves to no known ecosystem, so
	// a detector's own token survives there — the open vocabulary keeps its
	// say where the table has none.
	//
	// A generic fallback identity is read through the type it fell back
	// from, not the generic type it landed on. The qualifier is part of the
	// identity, so it is the same source of truth the rest of this
	// projection reads; construction kept the caller's ecosystem, and
	// reconstruction from the identity alone (NewDependencyNodeFromPURL, a
	// wire payload stating only its purl) used to come back with none. Same
	// identity, different ecosystem -- and ecosystem drives family seeding,
	// name handling, and display. A failed type the tables do not know
	// resolves to nothing, and the caller's token survives as it would for
	// any custom type.
	family := n.purl.Type
	if failedType, ok := genericFallbackType(n.purl); ok {
		family = failedType
	}
	if resolved := ecosystemForPURLType(family); resolved != "" {
		n.Ecosystem = resolved
	}
	// The identity is the single source of truth for these fields: name,
	// org, and version are projected from the canonical package URL
	// verbatim, never merged with caller values. Caller coordinates decide
	// what identity gets minted; once minted, the identity decides what the
	// coordinates say. That keeps presentation and registry seeding from
	// ever disagreeing with the key (a record keyed pkg:npm/foo@1 cannot
	// read as bar@2), preserves the spellings a purl type's rules allow,
	// and makes the codec idempotent by construction — one identity always
	// projects one set of coordinates. Path-style ecosystems keep their
	// native form through the accessors: a Go module projects as org
	// "github.com/example/lib" plus name "v2", which EcosystemName and
	// DisplayName rejoin into "github.com/example/lib/v2".
	n.Name = n.purl.Name
	n.Org = strings.TrimPrefix(n.purl.Namespace, "@")
	n.Version = n.purl.Version
	// Projected values are taken from the identity verbatim and are never
	// re-normalized: the package URL preserves spellings its type's rules
	// allow (an npm scope's case, an alphabetic version), and normalizing
	// the projection would leave coordinates naming a different package
	// than the key — a matcher querying by coordinates would look up
	// something the identity never claimed. Verbatim projection is also
	// what keeps the codec idempotent: the same identity always projects
	// the same coordinates, however many times a node round-trips.
}

// ecosystemForPURLType resolves the SDK ecosystem a purl type belongs to.
// The type table covers the types whose names differ from Bomly's
// ecosystem token (golang, gem, …); the canonical alias table covers the
// direct ones (npm, apk, rpm, conda, …), which the type table deliberately
// omits. Without the second lookup a node built from a bare package URL
// would carry no ecosystem, and ecosystem-specific behavior — an npm
// scope in EcosystemName(), for one — would silently degrade.
func ecosystemForPURLType(purlType string) Ecosystem {
	if ecosystem, ok := purlkit.EcosystemForType(purlType); ok {
		return Ecosystem(ecosystem)
	}
	if ecosystem, ok := purlkit.CanonicalEcosystem(purlType); ok {
		return Ecosystem(ecosystem)
	}
	return ""
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
	if len(n.Licenses) > 0 {
		clone.Licenses = append([]PackageLicense(nil), n.Licenses...)
	}
	clone.ExternalReferences = cloneExternalReferences(n.ExternalReferences)
	clone.Supplier = n.Supplier.Clone()
	clone.Originator = n.Originator.Clone()
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
