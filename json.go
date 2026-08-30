package sdk

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
)

// nodeWire is the flat protocol-v1 node payload: the legacy field set plus
// the additive kind discriminator, origins list, and declaring manifest
// path. Struct tags are the wire contract; every addition is omitempty.
type nodeWire struct {
	Kind                  NodeKind               `json:"kind,omitempty"`
	ID                    string                 `json:"id"`
	PURL                  string                 `json:"purl,omitempty"`
	Ecosystem             Ecosystem              `json:"ecosystem,omitempty"`
	PackageManager        PackageManager         `json:"package_manager,omitempty"`
	Type                  PackageType            `json:"type,omitempty"`
	Org                   string                 `json:"org,omitempty"`
	Name                  string                 `json:"name,omitempty"`
	Version               string                 `json:"version,omitempty"`
	Language              Language               `json:"language,omitempty"`
	FirstParty            bool                   `json:"first_party,omitempty"`
	Relationship          DependencyRelationship `json:"relationship,omitempty"`
	Source                DependencySource       `json:"source,omitempty"`
	Scopes                []Scope                `json:"scopes,omitempty"`
	Locations             []PackageLocation      `json:"locations,omitempty"`
	CPEs                  []string               `json:"cpes,omitempty"`
	Digests               []Digest               `json:"digests,omitempty"`
	Copyright             string                 `json:"copyright,omitempty"`
	FoundBy               string                 `json:"found_by,omitempty"`
	ResolvedURL           string                 `json:"resolved_url,omitempty"`
	Origin                *DependencyOrigin      `json:"origin,omitempty"`
	Origins               []DependencyOrigin     `json:"origins,omitempty"`
	DeclaringManifestPath string                 `json:"declaring_manifest_path,omitempty"`
	ManifestKind          ManifestKind           `json:"manifest_kind,omitempty"`
	Metadata              map[string]any         `json:"metadata,omitempty"`
	Matched               bool                   `json:"matched,omitempty"`
	PackageRef            string                 `json:"package_ref,omitempty"`
}

// wireKind resolves the node kind of a payload: an explicit kind is
// authoritative and wins over the legacy fields; a payload without one —
// every pre-union binary — infers deterministically: a manifest package
// type is a manifest, the first-party marker is a module, and everything
// else — including an application-typed component without the marker — is
// a dependency (application type alone is never an ownership signal,
// ADR-0015). An unrecognized kind is a decode error, never a guess.
func (w *nodeWire) wireKind() (NodeKind, error) {
	if w.Kind != "" {
		return ParseNodeKind(string(w.Kind))
	}
	if strings.EqualFold(strings.TrimSpace(string(w.Type)), string(PackageTypeManifest)) {
		return NodeKindManifest, nil
	}
	if w.FirstParty {
		return NodeKindModule, nil
	}
	return NodeKindDependency, nil
}

// wireOrigins unions the legacy singular origin field with the additive
// origins list, deduplicated by normalized value, so a payload carrying
// both never drops or double-counts origin evidence.
func (w *nodeWire) wireOrigins() []DependencyOrigin {
	var singular []DependencyOrigin
	if w.Origin != nil {
		singular = []DependencyOrigin{*w.Origin}
	}
	return MergeOrigins(singular, w.Origins)
}

// decodeNode reconstructs a typed node from its wire form through the
// constructor gates. The gates are strict: a dependency payload whose
// identity cannot mint a well-formed package URL is a decode error — the
// wire carries only valid identities, custom purl types included.
func (w *nodeWire) decodeNode() (GraphNode, error) {
	kind, err := w.wireKind()
	if err != nil {
		return nil, err
	}
	switch kind {
	case NodeKindManifest:
		return w.decodeManifestNode()
	case NodeKindModule:
		return w.decodeModuleNode()
	default:
		return w.decodeDependencyNode()
	}
}

func (w *nodeWire) manifestPath() string {
	if trimmed := strings.TrimPrefix(w.ID, manifestIDPrefix); trimmed != w.ID && strings.TrimSpace(trimmed) != "" {
		return trimmed
	}
	if w.DeclaringManifestPath != "" {
		return w.DeclaringManifestPath
	}
	for _, location := range w.Locations {
		if strings.TrimSpace(location.RealPath) != "" {
			return location.RealPath
		}
	}
	return w.Name
}

func (w *nodeWire) decodeManifestNode() (*ManifestNode, error) {
	node, err := NewManifestNode(w.manifestPath(), w.ManifestKind)
	if err != nil {
		return nil, fmt.Errorf("decode manifest node %q: %w", w.ID, err)
	}
	node.Metadata = w.Metadata
	return node, nil
}

func (w *nodeWire) decodeModuleNode() (*ModuleNode, error) {
	declaring := w.DeclaringManifestPath
	if declaring == "" {
		for _, location := range w.Locations {
			if strings.TrimSpace(location.RealPath) != "" {
				declaring = location.RealPath
				break
			}
		}
	}
	if declaring == "" {
		return nil, fmt.Errorf("decode module node %q: no declaring manifest path", w.ID)
	}
	node, err := NewModuleNode(declaring, w.coordinates())
	if err != nil {
		return nil, fmt.Errorf("decode module node %q: %w", w.ID, err)
	}
	node.Locations = w.Locations
	node.Metadata = w.Metadata
	return node, nil
}

func (w *nodeWire) decodeDependencyNode() (*DependencyNode, error) {
	node, err := newDependencyNode(w.coordinates(), strings.TrimSpace(w.PURL))
	if err != nil {
		return nil, fmt.Errorf("decode dependency node %q: %w", w.ID, err)
	}
	node.Relationship = w.Relationship
	node.Source = w.Source
	node.Scopes = w.Scopes
	node.Locations = w.Locations
	node.CPEs = w.CPEs
	node.Digests = w.Digests
	node.Copyright = w.Copyright
	node.FoundBy = w.FoundBy
	node.ResolvedURL = w.ResolvedURL
	node.Origins = MergeOrigins(node.Origins, w.wireOrigins())
	if len(w.Metadata) > 0 {
		if node.Metadata == nil {
			node.Metadata = make(map[string]any, len(w.Metadata))
		}
		for key, value := range w.Metadata {
			node.Metadata[key] = value
		}
	}
	node.Matched = w.Matched
	node.PackageRef = w.PackageRef
	return node, nil
}

func (w *nodeWire) coordinates() Coordinates {
	return Coordinates{
		PURL:           w.PURL,
		Ecosystem:      w.Ecosystem,
		PackageManager: w.PackageManager,
		Type:           w.Type,
		Org:            w.Org,
		Name:           w.Name,
		Version:        w.Version,
		Language:       w.Language,
	}
}

// encodeNodeWire renders a typed node into the flat wire form, dual-writing
// the legacy markers pre-union readers key on: manifest nodes emit the
// manifest package type, module nodes emit the first-party marker, and
// dependency nodes emit the legacy singular origin beside the origins list.
func encodeNodeWire(node GraphNode) nodeWire {
	switch n := node.(type) {
	case *ManifestNode:
		return nodeWire{
			Kind:         NodeKindManifest,
			ID:           n.NodeID(),
			Type:         PackageTypeManifest,
			Name:         path.Base(n.Path),
			ManifestKind: n.FileKind,
			Locations:    n.NodeLocations(),
			Metadata:     n.Metadata,
		}
	case *ModuleNode:
		return nodeWire{
			Kind:                  NodeKindModule,
			ID:                    n.NodeID(),
			PURL:                  n.PURL(),
			Ecosystem:             n.Ecosystem,
			PackageManager:        n.PackageManager,
			Type:                  n.Type,
			Org:                   n.Org,
			Name:                  n.Name,
			Version:               n.Version,
			Language:              n.Language,
			FirstParty:            true,
			DeclaringManifestPath: n.DeclaringManifestPath,
			Locations:             n.Locations,
			Metadata:              n.Metadata,
		}
	case *DependencyNode:
		wire := nodeWire{
			Kind:           NodeKindDependency,
			ID:             n.NodeID(),
			PURL:           n.Coordinates.PURL,
			Ecosystem:      n.Ecosystem,
			PackageManager: n.PackageManager,
			Type:           n.Type,
			Org:            n.Org,
			Name:           n.Name,
			Version:        n.Version,
			Language:       n.Language,
			Relationship:   n.Relationship,
			Source:         n.Source,
			Scopes:         n.Scopes,
			Locations:      n.Locations,
			CPEs:           n.CPEs,
			Digests:        n.Digests,
			Copyright:      n.Copyright,
			FoundBy:        n.FoundBy,
			ResolvedURL:    n.ResolvedURL,
			Origins:        n.Origins,
			Metadata:       n.Metadata,
			Matched:        n.Matched,
			PackageRef:     n.PackageRef,
		}
		if len(n.Origins) > 0 {
			legacy := n.Origins[0]
			wire.Origin = &legacy
		}
		return wire
	default:
		return nodeWire{}
	}
}

// MarshalJSON encodes a dependency node in its flat wire form.
func (n *DependencyNode) MarshalJSON() ([]byte, error) {
	wire := encodeNodeWire(n)
	return json.Marshal(wire)
}

// UnmarshalJSON decodes a dependency node through the constructor gates. A
// payload of a different node kind, or one whose identity cannot mint a
// well-formed package URL, is an error.
func (n *DependencyNode) UnmarshalJSON(data []byte) error {
	var wire nodeWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	kind, err := wire.wireKind()
	if err != nil {
		return err
	}
	if kind != NodeKindDependency {
		return fmt.Errorf("expected a dependency node, got kind %q", kind)
	}
	decoded, err := wire.decodeDependencyNode()
	if err != nil {
		return err
	}
	*n = *decoded
	return nil
}

type graphJSON struct {
	Nodes []nodeWire       `json:"nodes,omitempty"`
	Edges []DependencyEdge `json:"edges,omitempty"`
}

// DependencyEdge captures one directed relationship between node IDs.
type DependencyEdge struct {
	FromID string `json:"fromId"`
	ToID   string `json:"toId"`
}

// MarshalJSON encodes a graph as a stable transport-friendly adjacency list.
func (g *Graph) MarshalJSON() ([]byte, error) {
	if g == nil {
		return []byte("null"), nil
	}
	payload := graphJSON{
		Nodes: make([]nodeWire, 0, g.Size()),
	}
	g.WalkNodes(func(node GraphNode) bool {
		payload.Nodes = append(payload.Nodes, encodeNodeWire(node))
		return true
	})
	g.WalkEdges(func(from, to GraphNode) bool {
		payload.Edges = append(payload.Edges, DependencyEdge{FromID: from.NodeID(), ToID: to.NodeID()})
		return true
	})
	return json.Marshal(payload)
}

// UnmarshalJSON decodes a graph from the plugin transport adjacency list.
// Nodes are reconstructed through the constructor gates (strict: an invalid
// dependency identity fails the decode) and inserted with fold-by-identity
// semantics, so a legacy payload whose distinct wire IDs mint one canonical
// identity folds instead of erroring. Edges follow the wire-ID → identity
// mapping; an edge that becomes a self-edge after folding is dropped — the
// fold made it meaningless.
func (g *Graph) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*g = *New()
		return nil
	}
	var payload graphJSON
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}
	out := NewWithCapacity(len(payload.Nodes))
	idMapping := make(map[string]string, len(payload.Nodes))
	selfAliases := make([]string, 0, len(payload.Nodes))
	for i := range payload.Nodes {
		wire := &payload.Nodes[i]
		node, err := wire.decodeNode()
		if err != nil {
			return err
		}
		survivor, err := out.InsertNode(node)
		if err != nil {
			return err
		}
		if wire.ID != "" {
			// Two payload nodes reusing one wire ID while minting different
			// identities make every edge referencing it order-dependent.
			// The pre-union decoder rejected duplicate graph IDs outright;
			// this keeps that guarantee where it still means something.
			if previous, seen := idMapping[wire.ID]; seen && previous != survivor.NodeID() {
				return fmt.Errorf("%w: wire id %q maps to both %q and %q", ErrNodeAlreadyExist, wire.ID, previous, survivor.NodeID())
			}
			idMapping[wire.ID] = survivor.NodeID()
		}
		selfAliases = append(selfAliases, survivor.NodeID())
	}
	// Canonical self-aliases fill gaps only: a wire ID a payload actually
	// used always wins. Otherwise a node whose arbitrary wire ID happens to
	// equal another node's newly minted identity would have its edges
	// silently redirected to that other node, and reversing the node order
	// would change the result.
	for _, alias := range selfAliases {
		if _, claimed := idMapping[alias]; !claimed {
			idMapping[alias] = alias
		}
	}
	for _, edge := range payload.Edges {
		fromID, okFrom := idMapping[edge.FromID]
		toID, okTo := idMapping[edge.ToID]
		if !okFrom || !okTo {
			return fmt.Errorf("%w: edge %q -> %q", ErrNodeNotFound, edge.FromID, edge.ToID)
		}
		if fromID == toID {
			continue
		}
		if err := out.AddEdge(fromID, toID); err != nil {
			return err
		}
	}
	*g = *out
	return nil
}

// MarshalJSON encodes a package registry as a stable PURL-keyed object for
// plugin transport.
func (r *PackageRegistry) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	payload := make(map[string]*Package, r.Len())
	for _, pkg := range r.All() {
		if pkg == nil || pkg.PURL == "" {
			continue
		}
		payload[pkg.PURL] = pkg.Clone()
	}
	return json.Marshal(payload)
}

// UnmarshalJSON decodes a PURL-keyed package registry from plugin transport.
func (r *PackageRegistry) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*r = *NewPackageRegistry()
		return nil
	}
	payload := map[string]*Package{}
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}
	out := NewPackageRegistry()
	purls := make([]string, 0, len(payload))
	for purl := range payload {
		purls = append(purls, purl)
	}
	sort.Strings(purls)
	for _, purl := range purls {
		pkg := payload[purl]
		if pkg == nil {
			pkg = &Package{}
		}
		clone := pkg.Clone()
		clone.PURL = purl
		out.Add(clone)
	}
	*r = *out
	return nil
}

// MarshalJSON encodes a package manager by its canonical name.
func (p PackageManager) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.Name())
}

// UnmarshalJSON decodes a package manager from its canonical name.
func (p *PackageManager) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	if value == "" {
		*p = PackageManagerUnknown
		return nil
	}
	manager, err := ParsePackageManager(value)
	if err != nil {
		return fmt.Errorf("parse package manager: %w", err)
	}
	*p = manager
	return nil
}
