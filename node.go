package sdk

import (
	"fmt"
	"path"
	"strings"

	"github.com/bomly-dev/bomly-sdk/purlkit"
)

// NodeKind discriminates the sealed graph-node union (ADR-0041 in
// bomly-cli's dev-docs/adr). Exactly three kinds exist in protocol v1; a
// future kind means a v2 negotiation, so ParseNodeKind rejects anything
// else rather than guessing.
type NodeKind string

const (
	// NodeKindManifest is a structural file record: a package.json, a
	// lockfile, a build script. Identified by its path, never matched or
	// enriched.
	NodeKindManifest NodeKind = "manifest"
	// NodeKindModule is one of the scanned project's own artifacts: the
	// root project itself and every workspace or reactor module.
	// First-party ownership is the kind, not a flag.
	NodeKindModule NodeKind = "module"
	// NodeKindDependency is one resolved third-party package — the unit of
	// matching and enrichment. Its identity is its canonical package URL.
	NodeKindDependency NodeKind = "dependency"
)

// ParseNodeKind validates a wire-supplied kind value. An unrecognized kind
// is an error, never a guess: a v1 payload can only carry v1 kinds.
func ParseNodeKind(value string) (NodeKind, error) {
	switch NodeKind(value) {
	case NodeKindManifest, NodeKindModule, NodeKindDependency:
		return NodeKind(value), nil
	default:
		return "", fmt.Errorf("unknown graph node kind %q", value)
	}
}

// NodeWarningCode identifies a recoverable condition a node constructor
// recorded instead of failing.
type NodeWarningCode string

const (
	// NodeWarningMissingVersion marks a node whose package URL carries no
	// version. The purl specification leaves version optional, so absence is
	// visible rather than fatal.
	NodeWarningMissingVersion NodeWarningCode = "missing-version"
	// NodeWarningDroppedEvidenceQualifier marks a URL-valued evidence
	// qualifier whose value did not survive the origin gates and was
	// discarded entirely — a signed or tokenized link is never sanitized
	// into something publishable.
	NodeWarningDroppedEvidenceQualifier NodeWarningCode = "dropped-evidence-qualifier"
)

// NodeWarning is a recoverable, constructor-recorded observation about a
// node. Warnings are in-process state: they are re-derived wherever the
// node is reconstructed (the wire decoder runs the same constructor gates),
// so they never need to travel.
type NodeWarning struct {
	Code    NodeWarningCode
	Message string
}

// GraphNode is the sealed union of the three graph-node kinds. Only this
// package's ManifestNode, ModuleNode, and DependencyNode implement it: the
// unexported method seals the union, so a type switch over the three kinds
// is exhaustive. A node's published graph ID is its identity itself —
// canonical package URL for dependency nodes, kind-qualified canonical
// paths for module and manifest nodes — which makes IDs disjoint across
// kinds and identity comparison a string comparison on IDs.
type GraphNode interface {
	// NodeID returns the node's published graph ID: its identity.
	NodeID() string
	// Kind returns which member of the union this node is.
	Kind() NodeKind
	// NodeLocations returns the file locations that witnessed this node.
	NodeLocations() []PackageLocation
	// NodeWarnings returns the constructor-recorded recoverable conditions.
	NodeWarnings() []NodeWarning
	// CloneNode returns a deep copy of the node.
	CloneNode() GraphNode

	sealedGraphNode()
}

// CanonicalRepoPath is the constructor-enforced gate for every path that
// participates in node identity: the canonical repository-relative,
// slash-separated form. Backslashes normalize to slashes and the path is
// cleaned; an empty result, an absolute path, a drive-letter path, a parent
// escape, or a path carrying '#' or control characters is rejected — the
// module-ID grammar joins a path and a name with '#', and a raw checkout
// path would make identities vary across machines.
func CanonicalRepoPath(value string) (string, error) {
	cleaned := strings.ReplaceAll(value, "\\", "/")
	// Cleaning can expose surrounding whitespace a single trim would have
	// caught ("a /" cleans to "a "), so trim and clean to a fixed point —
	// canonical outputs must be idempotent inputs.
	for {
		next := strings.TrimSpace(cleaned)
		if next != "" {
			next = path.Clean(next)
		}
		if next == cleaned {
			break
		}
		cleaned = next
	}
	if cleaned == "" {
		return "", fmt.Errorf("identity path is empty")
	}
	for i := 0; i < len(cleaned); i++ {
		if c := cleaned[i]; c == '#' || c < 0x20 || c == 0x7f {
			return "", fmt.Errorf("identity path contains reserved byte %#x", c)
		}
	}
	if strings.HasPrefix(cleaned, "/") {
		return "", fmt.Errorf("identity path %q is absolute; use the repository-relative form", value)
	}
	if len(cleaned) >= 2 && cleaned[1] == ':' {
		return "", fmt.Errorf("identity path %q carries a drive letter; use the repository-relative form", value)
	}
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("identity path %q escapes the repository", value)
	}
	return cleaned, nil
}

const (
	manifestIDPrefix = "manifest:"
	moduleIDPrefix   = "module:"
	moduleIDJoiner   = "#"
)

// ManifestNode is the structural file record of the union: a manifest,
// lockfile, or build script. Its identity is its canonical
// repository-relative path, its published ID is "manifest:" + path, and it
// is never matched or enriched. The per-entry ManifestMetadata on
// GraphEntry remains the authoritative manifest record; a manifest node is
// the graph's projection of it (detectorkit.ManifestNodeForEntry derives
// one), with the public constructor covering nested workspace manifests.
type ManifestNode struct {
	// Path is the canonical repository-relative path (identity).
	Path string
	// FileKind classifies the manifest file, reusing the ManifestMetadata
	// vocabulary.
	FileKind ManifestKind
	// Metadata is the free-form escape hatch shared by all node kinds.
	Metadata map[string]any

	id string
}

// NewManifestNode constructs a manifest node from a repository-relative
// path. The path passes CanonicalRepoPath; there is no other gate.
func NewManifestNode(manifestPath string, kind ManifestKind) (*ManifestNode, error) {
	canonical, err := CanonicalRepoPath(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("manifest node: %w", err)
	}
	return &ManifestNode{Path: canonical, FileKind: kind, id: manifestIDPrefix + canonical}, nil
}

// NodeID returns "manifest:" + the canonical path.
func (n *ManifestNode) NodeID() string { return n.id }

// Kind returns NodeKindManifest.
func (n *ManifestNode) Kind() NodeKind { return NodeKindManifest }

// NodeLocations returns the manifest's own path as its single location.
func (n *ManifestNode) NodeLocations() []PackageLocation {
	return []PackageLocation{{RealPath: n.Path, AccessPath: n.Path}}
}

// NodeWarnings returns nil: manifest construction records no recoverable
// conditions.
func (n *ManifestNode) NodeWarnings() []NodeWarning { return nil }

// Clone returns a deep copy.
func (n *ManifestNode) Clone() *ManifestNode {
	if n == nil {
		return nil
	}
	clone := *n
	clone.Metadata = cloneAnyMap(n.Metadata)
	return &clone
}

// CloneNode implements GraphNode.
func (n *ManifestNode) CloneNode() GraphNode { return n.Clone() }

func (n *ManifestNode) sealedGraphNode() {}

// ModuleNode is one of the scanned project's own artifacts: the root
// project and every workspace or reactor module. Ownership is the kind —
// it cannot be dropped by a fold or asserted by an imported document — and
// module nodes are never matched or enriched. Identity is the declaring
// manifest path beside the canonical package URL when one is derivable, or
// beside the module name otherwise: a recursive scan can discover two
// unrelated projects with identical coordinates, and the path keeps those
// roots apart.
type ModuleNode struct {
	Coordinates
	// DeclaringManifestPath is the canonical repository-relative path of
	// the manifest that declares this module — always part of the identity.
	DeclaringManifestPath string
	// Locations are the file locations that witnessed the module.
	Locations []PackageLocation
	// Metadata is the free-form escape hatch shared by all node kinds.
	Metadata map[string]any

	id       string
	purl     string
	warnings []NodeWarning
}

// NewModuleNode constructs a module node. The declaring manifest path
// passes CanonicalRepoPath and always participates in identity. The
// coordinates are normalized, and a canonical package URL is derived when
// they allow one — under the same missing-version warning policy as
// dependency nodes — otherwise the module is identified by path and name,
// and the name is then required.
func NewModuleNode(declaringManifestPath string, coords Coordinates) (*ModuleNode, error) {
	canonicalPath, err := CanonicalRepoPath(declaringManifestPath)
	if err != nil {
		return nil, fmt.Errorf("module node: %w", err)
	}
	scratch := coords
	normalizeCoordinateVocabulary(&scratch)
	NormalizeCoordinates(&scratch)

	node := &ModuleNode{Coordinates: scratch, DeclaringManifestPath: canonicalPath}
	identityTail := ""
	// A module derives a PURL only when its coordinates genuinely allow one:
	// an explicit package URL, or a vocabulary value naming a known
	// ecosystem. The generic/verbatim fallback types are registry lookup
	// fabrications, and a module is the project's own record — without a
	// real ecosystem it is identified by path and name (ADR-0041).
	_, knownEcosystem := purlkit.CanonicalEcosystem(string(scratch.Ecosystem), scratch.PackageManager.Name(), string(scratch.Type))
	if minted := scratch.CanonicalPURL(); minted != "" && (knownEcosystem || strings.TrimSpace(coords.PURL) != "") {
		if identity, evidence, err := dependencyIdentityFromPURL(minted); err == nil {
			node.purl = identity.rendered
			node.Coordinates.PURL = identity.rendered
			identityTail = identity.rendered
			if identity.missingVersion {
				node.warnings = append(node.warnings, NodeWarning{
					Code:    NodeWarningMissingVersion,
					Message: "module package URL carries no version",
				})
			}
			_ = evidence // module origins are not modeled; evidence qualifiers are simply not identity
		}
	}
	if identityTail == "" {
		node.Coordinates.PURL = ""
		if strings.TrimSpace(scratch.Name) == "" {
			return nil, fmt.Errorf("module node: no package URL is derivable and the name is empty")
		}
		identityTail = scratch.Name
	}
	node.id = moduleIDPrefix + canonicalPath + moduleIDJoiner + identityTail
	return node, nil
}

// PURL returns the module's canonical package URL, or "" when none was
// derivable.
func (n *ModuleNode) PURL() string { return n.purl }

// NodeID returns "module:" + path + "#" + (canonical PURL | name).
func (n *ModuleNode) NodeID() string { return n.id }

// Kind returns NodeKindModule.
func (n *ModuleNode) Kind() NodeKind { return NodeKindModule }

// NodeLocations returns the module's witnessed locations.
func (n *ModuleNode) NodeLocations() []PackageLocation { return n.Locations }

// NodeWarnings returns the constructor-recorded recoverable conditions.
func (n *ModuleNode) NodeWarnings() []NodeWarning {
	return append([]NodeWarning(nil), n.warnings...)
}

// Clone returns a deep copy.
func (n *ModuleNode) Clone() *ModuleNode {
	if n == nil {
		return nil
	}
	clone := *n
	clone.Locations = clonePackageLocations(n.Locations)
	clone.Metadata = cloneAnyMap(n.Metadata)
	clone.warnings = append([]NodeWarning(nil), n.warnings...)
	return &clone
}

// CloneNode implements GraphNode.
func (n *ModuleNode) CloneNode() GraphNode { return n.Clone() }

func (n *ModuleNode) sealedGraphNode() {}

// clonePackageLocations deep-copies a location slice including positions.
func clonePackageLocations(locations []PackageLocation) []PackageLocation {
	if len(locations) == 0 {
		return nil
	}
	out := make([]PackageLocation, len(locations))
	for i, location := range locations {
		out[i] = location
		if location.Position != nil {
			out[i].Position = new(*location.Position)
		}
	}
	return out
}

// normalizeCoordinateVocabulary folds the closed discriminator vocabularies
// before any identity derivation: case for ecosystem, package manager, and
// type, and the ecosystem additionally through purlkit's canonical alias
// table — the wire accepts case variants of them verbatim, and "NPM" beside
// "npm" must mint one identity.
func normalizeCoordinateVocabulary(coords *Coordinates) {
	coords.Ecosystem = Ecosystem(strings.ToLower(strings.TrimSpace(string(coords.Ecosystem))))
	coords.PackageManager = PackageManager(strings.ToLower(strings.TrimSpace(coords.PackageManager.Name())))
	coords.Type = PackageType(strings.ToLower(strings.TrimSpace(string(coords.Type))))
	canonical, ok := purlkit.CanonicalEcosystem(string(coords.Ecosystem), coords.PackageManager.Name(), string(coords.Type))
	if !ok {
		return
	}
	// Adopting the canonical alias must never change the minted package URL
	// type: "cocoapods" folds to the swift ecosystem but mints pkg:cocoapods,
	// and rewriting the field before minting would fabricate a pkg:swift
	// identity the registry never issued (and fail its namespace profile).
	before := purlkit.TypeForValues(string(coords.Ecosystem), coords.PackageManager.Name(), string(coords.Type))
	after := purlkit.TypeForValues(canonical, coords.PackageManager.Name(), string(coords.Type))
	if before == after {
		coords.Ecosystem = Ecosystem(canonical)
	}
}
