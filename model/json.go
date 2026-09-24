package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"path"
	"sort"
	"strings"
)

// Decode bounds. A payload past any of them is refused before it is
// materialized, so what a reader allocates is bounded by what it accepted,
// not by what it was sent. The numbers are deliberately dumb -- bytes and
// counts -- and are frozen once pinned; there is nothing to tune in them.
const (
	// MaxPayloadBytes is the most a graph or registry payload may occupy on
	// the wire. It equals the SBOM ingest cap in package sbom: a graph is
	// what one ingestable document decodes to, and a payload that could not
	// have come from one is not accepted either.
	MaxPayloadBytes = 256 << 20
	// MaxGraphNodes bounds the nodes of one graph payload. The largest real
	// workspaces resolve to a few tens of thousands of dependencies; this is
	// five times that, and a decoder that admits it still allocates in
	// proportion to a count it has checked.
	MaxGraphNodes = 1 << 18
	// MaxGraphEdges bounds the edges of one graph payload: eight per node at
	// the node bound. Lockfile graphs average two to four edges a node, and
	// a dense workspace stays well under eight.
	MaxGraphEdges = 1 << 21
	// MaxRegistryPackages bounds one registry payload. A registry holds one
	// package per distinct package URL and never outgrows the dependency
	// nodes that seed it.
	MaxRegistryPackages = MaxGraphNodes
)

// ErrPayloadTooLarge is returned, wrapped with what was too large, by the
// graph and registry decoders when a payload exceeds a decode bound.
var ErrPayloadTooLarge = errors.New("payload exceeds the decode bound")

// The bounds a decoder consults. They are package variables rather than
// the constants directly so a test can shrink them and exercise a refusal
// without building a payload the size of the real bound.
var (
	graphDecodeBounds    = graphBounds{bytes: MaxPayloadBytes, nodes: MaxGraphNodes, edges: MaxGraphEdges}
	registryDecodeBounds = registryBounds{bytes: MaxPayloadBytes, packages: MaxRegistryPackages}
)

type graphBounds struct{ bytes, nodes, edges int }

type registryBounds struct{ bytes, packages int }

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
	SourceScope           string                 `json:"source_scope,omitempty"`
	Locations             []PackageLocation      `json:"locations,omitempty"`
	CPEs                  []string               `json:"cpes,omitempty"`
	Digests               []Digest               `json:"digests,omitempty"`
	Copyright             string                 `json:"copyright,omitempty"`
	FoundBy               string                 `json:"found_by,omitempty"`
	ResolvedURL           string                 `json:"resolved_url,omitempty"`
	Origin                *DependencyOrigin      `json:"origin,omitempty"`
	Origins               []DependencyOrigin     `json:"origins,omitempty"`
	Licenses              []PackageLicense       `json:"licenses,omitempty"`
	ExternalReferences    []ExternalReference    `json:"external_references,omitempty"`
	Description           string                 `json:"description,omitempty"`
	Homepage              string                 `json:"homepage,omitempty"`
	Supplier              *Contact               `json:"supplier,omitempty"`
	Originator            *Contact               `json:"originator,omitempty"`
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
	node.SourceScope = NormalizeSourceScope(w.SourceScope)
	node.Locations = w.Locations
	node.CPEs = w.CPEs
	// Routed through the set merge so a digest the codec rejected does not
	// survive as a zero element that re-encodes to an empty checksum record.
	node.Digests = mergeDigestSet(nil, w.Digests)
	node.Copyright = NormalizeCopyright(w.Copyright)
	node.FoundBy = w.FoundBy
	node.ResolvedURL = w.ResolvedURL
	node.Origins = MergeOrigins(node.Origins, w.wireOrigins())
	// MergeLicenses re-runs each claim's gate, so a payload that reached the
	// slice without passing through PackageLicense's codec — a hand-built
	// value, or one an older producer wrote — is still held to it here.
	node.Licenses = MergeLicenses(nil, w.Licenses)
	node.ExternalReferences = MergeExternalReferences(nil, w.ExternalReferences)
	node.Description = NormalizeDescription(w.Description)
	node.Homepage = NormalizeHomepage(w.Homepage)
	// normalizedContact returns nil for a contact the codec rejected, so a
	// payload like {"kind":"organization"} with no name does not leave a
	// non-nil pointer to a zero value that re-encodes as "supplier":{}.
	node.Supplier = normalizedContact(w.Supplier)
	node.Originator = normalizedContact(w.Originator)
	if len(w.Metadata) > 0 {
		if node.Metadata == nil {
			node.Metadata = make(map[string]any, len(w.Metadata))
		}
		maps.Copy(node.Metadata, w.Metadata)
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
			SourceScope:    NormalizeSourceScope(n.SourceScope),
			Locations:      n.Locations,
			CPEs:           n.CPEs,
			Digests:        mergeDigestSet(nil, n.Digests),
			Copyright:      NormalizeCopyright(n.Copyright),
			FoundBy:        n.FoundBy,
			ResolvedURL:    n.ResolvedURL,
			Origins:        n.Origins,
			Metadata:       n.Metadata,
			Matched:        n.Matched,
			PackageRef:     n.PackageRef,
			// Re-gated on the way out as well as in, so a field set directly
			// on a hand-built node never reaches a reader unchecked.
			Licenses:           MergeLicenses(nil, n.Licenses),
			ExternalReferences: MergeExternalReferences(nil, n.ExternalReferences),
			Description:        NormalizeDescription(n.Description),
			Homepage:           NormalizeHomepage(n.Homepage),
			Supplier:           normalizedContact(n.Supplier),
			Originator:         normalizedContact(n.Originator),
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
//
// Kind is additive and omitted when unknown, so a payload written before the
// field keeps its exact bytes. On decode an absent kind is derived from the
// nodes the edge joins, which is why adding the field did not need a wire
// break: the structure already carried the answer.
type DependencyEdge struct {
	FromID string   `json:"fromId"`
	ToID   string   `json:"toId"`
	Kind   EdgeKind `json:"kind,omitempty"`
}

// MarshalJSON encodes a graph as a stable transport-friendly adjacency list.
//
// Stable means byte-stable: nodes are written in ascending node-ID order and
// edges in ascending (fromId, toId) order, so two graphs with the same
// content encode to the same bytes whatever order their nodes were added in,
// and whether a node was removed and added back. The slot order the graph
// keeps internally reuses freed slots and the adjacency maps iterate in Go's
// randomized order, so walking either would put the insertion history into
// the payload -- which is what a digest over these bytes must not see.
func (g *Graph) MarshalJSON() ([]byte, error) {
	if g == nil {
		return []byte("null"), nil
	}
	payload := graphJSON{
		Nodes: make([]nodeWire, 0, g.Size()),
	}
	order := g.sortedIndices()
	for _, idx := range order {
		payload.Nodes = append(payload.Nodes, encodeNodeWire(g.nodes[idx]))
	}
	for _, fromIdx := range order {
		relationships := g.outgoing[fromIdx]
		if len(relationships) == 0 {
			continue
		}
		from := g.nodes[fromIdx]
		for _, toIdx := range g.sortedAdjacent(relationships) {
			if !g.alive[toIdx] {
				continue
			}
			to := g.nodes[toIdx]
			kind := relationships[toIdx]
			edge := DependencyEdge{FromID: from.NodeID(), ToID: to.NodeID()}
			// The kind is written only when the structure does not already
			// imply it. A decoder derives an absent kind from the nodes, so
			// writing a derived value would add bytes that say nothing -- and
			// would change every existing payload, which is exactly what an
			// additive field must not do. What survives here is a kind that
			// contradicts derivation, which is the only kind a reader could
			// not reconstruct.
			if kind != DeriveEdgeKind(from, to) {
				edge.Kind = kind
			}
			payload.Edges = append(payload.Edges, edge)
		}
	}
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
	// The byte bound comes first, before a decoder exists: the count bounds
	// keep the elements past them from being decoded, but say nothing about
	// the size of the ones before them.
	if len(data) > graphDecodeBounds.bytes {
		return fmt.Errorf("%w: graph: %d bytes, over %d", ErrPayloadTooLarge, len(data), graphDecodeBounds.bytes)
	}
	payload, err := decodeGraphPayload(data, graphDecodeBounds)
	if err != nil {
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
		if err := out.AddTypedEdge(fromID, toID, edge.Kind); err != nil {
			return err
		}
	}
	*g = *out
	return nil
}

// decodeGraphPayload reads the adjacency-list object one element at a time
// and refuses it as soon as a section passes its count bound. Over-count is
// an error rather than a truncation: a graph with its tail cut off is a
// smaller graph that scans clean, which is the one way a decoder must not
// fail. A repeated "nodes" or "edges" key is refused too -- encoding/json
// would keep the last and silently discard the rest, and Bomly never writes
// one. Unknown keys are skipped, and the two sections may come in any order.
func decodeGraphPayload(data []byte, bounds graphBounds) (graphJSON, error) {
	var payload graphJSON
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := expectDelim(decoder, '{', "graph"); err != nil {
		return payload, err
	}
	seen := make(map[string]struct{}, 2)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return payload, fmt.Errorf("graph: %w", err)
		}
		key, _ := token.(string)
		switch key {
		case "nodes", "edges":
			if _, dup := seen[key]; dup {
				return payload, fmt.Errorf("graph: %q key repeated", key)
			}
			seen[key] = struct{}{}
		default:
			var skip json.RawMessage
			if err := decoder.Decode(&skip); err != nil {
				return payload, fmt.Errorf("graph: %q: %w", key, err)
			}
			continue
		}
		if key == "nodes" {
			err = decodeBoundedArray(decoder, bounds.nodes, "graph nodes", func() error {
				var node nodeWire
				if err := decoder.Decode(&node); err != nil {
					return err
				}
				payload.Nodes = append(payload.Nodes, node)
				return nil
			})
		} else {
			err = decodeBoundedArray(decoder, bounds.edges, "graph edges", func() error {
				var edge DependencyEdge
				if err := decoder.Decode(&edge); err != nil {
					return err
				}
				payload.Edges = append(payload.Edges, edge)
				return nil
			})
		}
		if err != nil {
			return payload, err
		}
	}
	if err := expectDelim(decoder, '}', "graph"); err != nil {
		return payload, err
	}
	if err := expectEnd(decoder, "graph"); err != nil {
		return payload, err
	}
	return payload, nil
}

// decodeBoundedArray reads an array element by element through element,
// refusing the array once it holds more than bound elements. A null array is
// empty.
func decodeBoundedArray(decoder *json.Decoder, bound int, what string, element func() error) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if token == nil {
		return nil
	}
	if delim, ok := token.(json.Delim); !ok || delim != '[' {
		return fmt.Errorf("%s: expected an array, got %v", what, token)
	}
	count := 0
	for decoder.More() {
		if count >= bound {
			return fmt.Errorf("%w: %s: more than %d elements", ErrPayloadTooLarge, what, bound)
		}
		if err := element(); err != nil {
			return fmt.Errorf("%s[%d]: %w", what, count, err)
		}
		count++
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	return nil
}

func expectDelim(decoder *json.Decoder, want json.Delim, what string) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if delim, ok := token.(json.Delim); !ok || delim != want {
		return fmt.Errorf("%s: expected %q, got %v", what, want, token)
	}
	return nil
}

// expectEnd mirrors what json.Unmarshal enforces: nothing but whitespace may
// follow the value.
func expectEnd(decoder *json.Decoder, what string) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s: trailing data after the payload", what)
	}
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
		// Package's own codec re-gates each record as it is written, so a
		// value installed after insertion -- Ensure, Get, and All all hand
		// back mutable pointers -- cannot cross the wire unchecked. The gate
		// lives on the type rather than here because package updates on a
		// matcher result never pass through this registry at all.
		//
		// No defensive copy: that codec has a value receiver, so it
		// normalizes its own copy and cannot rewrite the stored record. A
		// clone here would deep-copy every package on every marshal to
		// prevent something that can no longer happen.
		payload[pkg.PURL] = pkg
	}
	return json.Marshal(payload)
}

// UnmarshalJSON decodes a PURL-keyed package registry from plugin transport.
func (r *PackageRegistry) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*r = *NewPackageRegistry()
		return nil
	}
	if len(data) > registryDecodeBounds.bytes {
		return fmt.Errorf("%w: package registry: %d bytes, over %d", ErrPayloadTooLarge, len(data), registryDecodeBounds.bytes)
	}
	type entry struct {
		purl string
		pkg  *Package
	}
	// Read one member at a time, bounded by the count of distinct package
	// URLs. A repeated key replaces the earlier member, which is what the
	// map this replaced did; what changes is that the bound is checked
	// before each new package is decoded rather than after all of them are.
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := expectDelim(decoder, '{', "package registry"); err != nil {
		return err
	}
	entries := make([]entry, 0, 16)
	index := make(map[string]int, 16)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("package registry: %w", err)
		}
		purl, _ := token.(string)
		at, seen := index[purl]
		if !seen && len(entries) >= registryDecodeBounds.packages {
			return fmt.Errorf("%w: package registry: more than %d packages", ErrPayloadTooLarge, registryDecodeBounds.packages)
		}
		var pkg *Package
		if err := decoder.Decode(&pkg); err != nil {
			return fmt.Errorf("package registry[%q]: %w", purl, err)
		}
		if seen {
			entries[at].pkg = pkg
			continue
		}
		index[purl] = len(entries)
		entries = append(entries, entry{purl: purl, pkg: pkg})
	}
	if err := expectDelim(decoder, '}', "package registry"); err != nil {
		return err
	}
	if err := expectEnd(decoder, "package registry"); err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].purl < entries[j].purl })
	out := NewPackageRegistry()
	for _, e := range entries {
		pkg := e.pkg
		if pkg == nil {
			pkg = &Package{}
		}
		clone := pkg.Clone()
		clone.PURL = e.purl
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
