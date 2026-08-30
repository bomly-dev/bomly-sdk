package sdk

import (
	"container/heap"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-sdk/purlkit"
)

var (
	ErrNilNode          = errors.New("graph node is nil")
	ErrEmptyNodeID      = errors.New("graph node id is empty")
	ErrNodeAlreadyExist = errors.New("graph node already exists")
	ErrNodeNotFound     = errors.New("graph node not found")
	ErrSelfDependency   = errors.New("self dependency is not allowed")
	ErrCycleDetected    = errors.New("dependency creates a cycle")
)

// Path describes one path through the graph. Paths are heterogeneous: they
// traverse manifest and module nodes on their way to dependencies.
type Path struct {
	Nodes   []GraphNode
	Cyclic  bool
	CycleTo string
}

// Diff summarizes the dependency changes between two graphs. Diffs are
// dependency-only: manifest and module nodes are structural and do not
// participate.
type Diff struct {
	Added       []*DependencyNode
	Removed     []*DependencyNode
	Updated     []VersionChange
	Transitions []DependencyDetailTransition
}

// VersionChange captures a dependency identity that changed versions.
type VersionChange struct {
	Before *DependencyNode
	After  *DependencyNode
}

// DependencyDetailField identifies one dependency property that changed
// independently of package identity or version.
type DependencyDetailField string

const (
	// DependencyDetailRelationship is a direct, transitive, or unknown
	// relationship change.
	DependencyDetailRelationship DependencyDetailField = "relationship"
	// DependencyDetailSource is a registry, workspace, file, Git, URL, or
	// project source change.
	DependencyDetailSource DependencyDetailField = "source"
	// DependencyDetailRegistryEligibility indicates that external registry
	// matching eligibility changed.
	DependencyDetailRegistryEligibility DependencyDetailField = "registry_eligibility"
)

// DependencyDetailTransition captures same-identity dependency detail changes.
// Version changes remain represented separately by VersionChange.
type DependencyDetailTransition struct {
	Before                 *DependencyNode         `json:"before"`
	After                  *DependencyNode         `json:"after"`
	ChangedFields          []DependencyDetailField `json:"changedFields"`
	BeforeRelationship     DependencyRelationship  `json:"beforeRelationship,omitempty"`
	AfterRelationship      DependencyRelationship  `json:"afterRelationship,omitempty"`
	BeforeRegistryEligible bool                    `json:"beforeRegistryEligible"`
	AfterRegistryEligible  bool                    `json:"afterRegistryEligible"`
}

// DependencyDetailReviewReason explains why a dependency detail change should
// receive extra review.
type DependencyDetailReviewReason string

const (
	// DependencyDetailReviewSourceGit indicates that the dependency now comes
	// from a Git repository.
	DependencyDetailReviewSourceGit DependencyDetailReviewReason = "source-changed-to-git"
	// DependencyDetailReviewSourceURL indicates that the dependency now comes
	// from an arbitrary URL.
	DependencyDetailReviewSourceURL DependencyDetailReviewReason = "source-changed-to-url"
)

// ReviewReasons returns the reasons this detail change needs extra review.
// The result is deterministic and does not treat missing evidence, coverage
// gains, or relationship-only changes as review signals.
func (t DependencyDetailTransition) ReviewReasons() []DependencyDetailReviewReason {
	reasons := make([]DependencyDetailReviewReason, 0, 1)
	if dependencyDetailFieldIncluded(t.ChangedFields, DependencyDetailSource) &&
		t.Before != nil && strings.TrimSpace(string(t.Before.Source)) != "" &&
		t.After != nil {
		switch t.After.Source {
		case DependencySourceGit:
			reasons = append(reasons, DependencyDetailReviewSourceGit)
		case DependencySourceURL:
			reasons = append(reasons, DependencyDetailReviewSourceURL)
		}
	}
	return reasons
}

// NeedsReview reports whether this detail change has at least one review reason.
func (t DependencyDetailTransition) NeedsReview() bool {
	return len(t.ReviewReasons()) > 0
}

// CloneDependencyDetailTransitions returns a deep copy of dependency detail
// transitions suitable for crossing component and plugin boundaries.
func CloneDependencyDetailTransitions(transitions []DependencyDetailTransition) []DependencyDetailTransition {
	if transitions == nil {
		return nil
	}
	cloned := make([]DependencyDetailTransition, len(transitions))
	for index, transition := range transitions {
		cloned[index] = transition
		cloned[index].ChangedFields = append([]DependencyDetailField(nil), transition.ChangedFields...)
		if transition.Before != nil {
			cloned[index].Before = transition.Before.Clone()
		}
		if transition.After != nil {
			cloned[index].After = transition.After.Clone()
		}
	}
	return cloned
}

func dependencyDetailFieldIncluded(fields []DependencyDetailField, wanted DependencyDetailField) bool {
	for _, field := range fields {
		if field == wanted {
			return true
		}
	}
	return false
}

// Graph stores the typed graph nodes as a directed graph, keyed by NodeID.
// A node's ID is its identity (ADR-0041), so the ID index doubles as the
// identity index: two nodes are the same node exactly when their IDs match.
type Graph struct {
	indexByID map[string]int
	nodes     []GraphNode
	alive     []bool
	outgoing  []map[int]struct{}
	incoming  []map[int]struct{}
	free      []int
	size      int
}

// New creates an empty graph.
func New() *Graph {
	return NewWithCapacity(0)
}

// NewWithCapacity creates an empty graph sized for the expected node count.
func NewWithCapacity(nodeCount int) *Graph {
	return &Graph{
		indexByID: make(map[string]int, nodeCount),
		nodes:     make([]GraphNode, 0, nodeCount),
		alive:     make([]bool, 0, nodeCount),
		outgoing:  make([]map[int]struct{}, 0, nodeCount),
		incoming:  make([]map[int]struct{}, 0, nodeCount),
	}
}

// AddNode inserts a node, rejecting a duplicate identity. Use InsertNode
// for fold-by-identity insertion.
func (g *Graph) AddNode(node GraphNode) error {
	if isNilNode(node) {
		return ErrNilNode
	}
	if node.NodeID() == "" {
		return ErrEmptyNodeID
	}
	if _, exists := g.indexByID[node.NodeID()]; exists {
		return fmt.Errorf("%w: %s", ErrNodeAlreadyExist, node.NodeID())
	}

	idx := g.nextSlot()
	g.nodes[idx] = node
	g.alive[idx] = true
	g.outgoing[idx] = make(map[int]struct{})
	g.incoming[idx] = make(map[int]struct{})
	g.indexByID[node.NodeID()] = idx
	g.size++
	return nil
}

// InsertNode is fold-by-identity insertion (ADR-0041): a node whose
// identity already exists in the graph unions into the existing record and
// the survivor is returned. Identity is the node ID, and IDs are disjoint
// across kinds, so a fold always joins records of one kind. Dependency
// folds union scopes, locations, and origins, merge the relationship, and
// fold registry-match eligibility toward eligible (any-witness: when
// exactly one witness is eligible, its source survives — withholding
// enrichment from a package a registry release genuinely uses would hide
// vulnerabilities). Module folds union locations; manifest folds are
// no-ops beyond the identity match.
func (g *Graph) InsertNode(node GraphNode) (GraphNode, error) {
	if isNilNode(node) {
		return nil, ErrNilNode
	}
	if node.NodeID() == "" {
		return nil, ErrEmptyNodeID
	}
	existing, ok := g.Node(node.NodeID())
	if !ok {
		if err := g.AddNode(node); err != nil {
			return nil, err
		}
		return node, nil
	}
	foldNodes(existing, node)
	return existing, nil
}

// isNilNode reports whether a GraphNode is absent — including a typed nil
// such as (*DependencyNode)(nil), which is a non-nil interface value whose
// methods would panic. A failed constructor's zero return must surface as
// ErrNilNode, not a crash.
func isNilNode(node GraphNode) bool {
	switch n := node.(type) {
	case nil:
		return true
	case *ManifestNode:
		return n == nil
	case *ModuleNode:
		return n == nil
	case *DependencyNode:
		return n == nil
	default:
		return false
	}
}

// foldNodes unions one witness into the surviving record of the same
// identity. Kinds always match because IDs are kind-disjoint.
func foldNodes(surviving, witness GraphNode) {
	switch survivor := surviving.(type) {
	case *DependencyNode:
		incoming, ok := witness.(*DependencyNode)
		if !ok {
			return
		}
		survivor.Relationship = MergeDependencyRelationship(survivor.Relationship, incoming.Relationship)
		for _, scope := range incoming.Scopes {
			survivor.AddScope(scope)
		}
		mergeNodeLocations(&survivor.Locations, incoming.Locations)
		survivor.Origins = MergeOrigins(survivor.Origins, incoming.Origins)
		mergeDependencySources(survivor, incoming)
		// Every witness's assertions about one package survive the fold:
		// security identifiers and integrity claims union, detection
		// scalars and metadata fill gaps. Dropping them would lose CPEs or
		// digests from a second SBOM witness on insertion order alone.
		survivor.CPEs = mergeStringSet(survivor.CPEs, incoming.CPEs)
		survivor.Digests = mergeDigestSet(survivor.Digests, incoming.Digests)
		// License claims are a set for the same reason they are on Package: a
		// declaration and a conclusion are two claims about one package, and
		// two witnesses that read different sources both have something to
		// say.
		survivor.Licenses = MergeLicenses(survivor.Licenses, incoming.Licenses)
		// The component-level document assertions are scalars — one supplier,
		// one homepage — so a later witness contributes only what the first
		// did not know.
		if strings.TrimSpace(survivor.Description) == "" {
			survivor.Description = incoming.Description
		}
		if survivor.Homepage == "" {
			survivor.Homepage = incoming.Homepage
		}
		if survivor.Supplier == nil {
			survivor.Supplier = incoming.Supplier.Clone()
		}
		if survivor.Originator == nil {
			survivor.Originator = incoming.Originator.Clone()
		}
		if survivor.Copyright == "" {
			survivor.Copyright = incoming.Copyright
		}
		if survivor.FoundBy == "" {
			survivor.FoundBy = incoming.FoundBy
		}
		if survivor.ResolvedURL == "" {
			survivor.ResolvedURL = incoming.ResolvedURL
		}
		if survivor.PackageRef == "" {
			survivor.PackageRef = incoming.PackageRef
		}
		// Classification the identity cannot project also fills gaps: a
		// bare-package-URL witness folded first would otherwise leave the
		// node with an unknown package manager, which manager-specific
		// consumers (remediation hints, most of all) key on.
		if survivor.PackageManager == PackageManagerUnknown {
			survivor.PackageManager = incoming.PackageManager
		}
		if survivor.Language == "" {
			survivor.Language = incoming.Language
		}
		if survivor.Type == "" {
			survivor.Type = incoming.Type
		}
		// Enrichment is an any-witness fact: one witness having been
		// matched is true of the folded record.
		survivor.Matched = survivor.Matched || incoming.Matched
		survivor.Metadata = mergeMetadata(survivor.Metadata, incoming.Metadata)
	case *ModuleNode:
		incoming, ok := witness.(*ModuleNode)
		if !ok {
			return
		}
		// A module identified by path and name carries no version in its
		// identity, so two witnesses of one module — one versionless —
		// fold, and without this the survivor's empty version would let
		// insertion order decide what gets published.
		if survivor.Version == "" {
			survivor.Version = incoming.Version
		}
		if survivor.Ecosystem == "" {
			survivor.Ecosystem = incoming.Ecosystem
		}
		if survivor.PackageManager == PackageManagerUnknown {
			survivor.PackageManager = incoming.PackageManager
		}
		if survivor.Language == "" {
			survivor.Language = incoming.Language
		}
		mergeNodeLocations(&survivor.Locations, incoming.Locations)
		survivor.Metadata = mergeMetadata(survivor.Metadata, incoming.Metadata)
	case *ManifestNode:
		incoming, ok := witness.(*ManifestNode)
		if !ok {
			return
		}
		// A manifest's classification lives only on the node, so an
		// unclassified first witness must not block a later classified one
		// — otherwise consolidation order decides whether the POM,
		// lockfile, or workflow kind survives.
		if survivor.FileKind == "" {
			survivor.FileKind = incoming.FileKind
		}
		survivor.Metadata = mergeMetadata(survivor.Metadata, incoming.Metadata)
	}
}

// mergeStringSet unions two string slices, preserving order and dropping
// duplicates.
func mergeStringSet(existing, additions []string) []string {
	if len(additions) == 0 {
		return existing
	}
	seen := make(map[string]struct{}, len(existing)+len(additions))
	for _, value := range existing {
		seen[value] = struct{}{}
	}
	for _, value := range additions {
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		existing = append(existing, value)
	}
	return existing
}

// mergeDigestSet unions two digest slices. Digests compare by whole value:
// algorithm, value, and subject together, since a digest of a different
// subject is a different claim.
func mergeDigestSet(existing, additions []Digest) []Digest {
	if len(additions) == 0 {
		return existing
	}
	seen := make(map[Digest]struct{}, len(existing)+len(additions))
	for _, digest := range existing {
		seen[digest] = struct{}{}
	}
	for _, digest := range additions {
		if _, duplicate := seen[digest]; duplicate {
			continue
		}
		seen[digest] = struct{}{}
		existing = append(existing, digest)
	}
	return existing
}

// mergeMetadata fills the gaps in existing from additions. Keys the
// survivor already carries win, so a fold never rewrites an assertion the
// surviving record made.
func mergeMetadata(existing, additions map[string]any) map[string]any {
	if len(additions) == 0 {
		return existing
	}
	if existing == nil {
		existing = make(map[string]any, len(additions))
	}
	for key, value := range additions {
		if _, present := existing[key]; present {
			continue
		}
		existing[key] = value
	}
	return existing
}

// mergeDependencySources folds registry-match eligibility toward eligible:
// when the surviving record is ineligible and the witness is eligible, the
// witness's source survives. Eligibility is computed per witness, so the
// Swift source-control special case and the unknown-source rule apply
// unchanged.
func mergeDependencySources(surviving, witness *DependencyNode) {
	if surviving.RegistryMatchEligible() || !witness.RegistryMatchEligible() {
		return
	}
	surviving.Source = witness.Source
}

// mergeNodeLocations appends the locations dst does not already carry.
func mergeNodeLocations(dst *[]PackageLocation, additions []PackageLocation) {
	for _, location := range additions {
		if !hasDependencyLocation(*dst, location) {
			*dst = append(*dst, location)
		}
	}
}

// Node returns a node by ID.
func (g *Graph) Node(id string) (GraphNode, bool) {
	idx, ok := g.indexByID[id]
	if !ok {
		return nil, false
	}
	return g.nodes[idx], ok
}

// DependencyNode returns the dependency node with the given ID, or false
// when the ID is absent or names a different kind.
func (g *Graph) DependencyNode(id string) (*DependencyNode, bool) {
	node, ok := g.Node(id)
	if !ok {
		return nil, false
	}
	dep, ok := node.(*DependencyNode)
	return dep, ok
}

// Nodes returns all nodes sorted by ID.
func (g *Graph) Nodes() []GraphNode {
	indices := g.sortedIndices()
	out := make([]GraphNode, 0, len(indices))
	for _, idx := range indices {
		out = append(out, g.nodes[idx])
	}
	return out
}

// DependencyNodes returns all dependency nodes sorted by ID — the iteration
// surface for matching, enrichment, and diffing, which are dependency-only.
func (g *Graph) DependencyNodes() []*DependencyNode {
	out := make([]*DependencyNode, 0, g.size)
	for _, idx := range g.sortedIndices() {
		if dep, ok := g.nodes[idx].(*DependencyNode); ok {
			out = append(out, dep)
		}
	}
	return out
}

// ModuleNodes returns all module nodes sorted by ID.
func (g *Graph) ModuleNodes() []*ModuleNode {
	out := make([]*ModuleNode, 0, g.size)
	for _, idx := range g.sortedIndices() {
		if module, ok := g.nodes[idx].(*ModuleNode); ok {
			out = append(out, module)
		}
	}
	return out
}

// ManifestNodes returns all manifest nodes sorted by ID.
func (g *Graph) ManifestNodes() []*ManifestNode {
	out := make([]*ManifestNode, 0, g.size)
	for _, idx := range g.sortedIndices() {
		if manifest, ok := g.nodes[idx].(*ManifestNode); ok {
			out = append(out, manifest)
		}
	}
	return out
}

// AddEdge adds a dependency relationship fromID -> toID, meaning fromID
// depends on toID.
func (g *Graph) AddEdge(fromID, toID string) error {
	if fromID == toID {
		return ErrSelfDependency
	}
	fromIdx, err := g.requireIndex(fromID)
	if err != nil {
		return err
	}
	toIdx, err := g.requireIndex(toID)
	if err != nil {
		return err
	}
	if _, ok := g.outgoing[fromIdx][toIdx]; ok {
		return nil
	}
	g.outgoing[fromIdx][toIdx] = struct{}{}
	g.incoming[toIdx][fromIdx] = struct{}{}
	return nil
}

// RemoveEdge removes a dependency relationship and reports whether it existed.
func (g *Graph) RemoveEdge(fromID, toID string) bool {
	fromIdx, ok := g.indexByID[fromID]
	if !ok {
		return false
	}
	toIdx, ok := g.indexByID[toID]
	if !ok {
		return false
	}
	if _, ok = g.outgoing[fromIdx][toIdx]; !ok {
		return false
	}
	delete(g.outgoing[fromIdx], toIdx)
	delete(g.incoming[toIdx], fromIdx)
	return true
}

// RemoveNode removes a node and all incident relationships.
func (g *Graph) RemoveNode(id string) bool {
	idx, ok := g.indexByID[id]
	if !ok {
		return false
	}
	for depIdx := range g.outgoing[idx] {
		delete(g.incoming[depIdx], idx)
	}
	for parentIdx := range g.incoming[idx] {
		delete(g.outgoing[parentIdx], idx)
	}
	delete(g.indexByID, id)
	g.nodes[idx] = nil
	g.alive[idx] = false
	g.outgoing[idx] = nil
	g.incoming[idx] = nil
	g.free = append(g.free, idx)
	g.size--
	return true
}

// DirectDependencies returns direct dependencies for a node, sorted by ID.
func (g *Graph) DirectDependencies(id string) ([]GraphNode, error) {
	idx, err := g.requireIndex(id)
	if err != nil {
		return nil, err
	}
	return g.lookupSorted(g.outgoing[idx]), nil
}

// Dependents returns direct dependents for a node, sorted by ID.
func (g *Graph) Dependents(id string) ([]GraphNode, error) {
	idx, err := g.requireIndex(id)
	if err != nil {
		return nil, err
	}
	return g.lookupSorted(g.incoming[idx]), nil
}

// Roots returns nodes with no incoming relationships.
func (g *Graph) Roots() []GraphNode {
	out := make([]GraphNode, 0, g.size)
	for _, idx := range g.sortedIndices() {
		if len(g.incoming[idx]) == 0 {
			out = append(out, g.nodes[idx])
		}
	}
	return out
}

// Leaves returns nodes with no outgoing relationships.
func (g *Graph) Leaves() []GraphNode {
	out := make([]GraphNode, 0, g.size)
	for _, idx := range g.sortedIndices() {
		if len(g.outgoing[idx]) == 0 {
			out = append(out, g.nodes[idx])
		}
	}
	return out
}

// CollectPathsTo returns deterministic root-to-target paths.
func (g *Graph) CollectPathsTo(targetID string) ([]Path, error) {
	targetIdx, err := g.requireIndex(targetID)
	if err != nil {
		return nil, err
	}

	relevant := g.reverseReachable(targetIdx)
	starts := g.relevantRoots(relevant)
	if len(starts) == 0 {
		starts = g.sortedRelevantIndices(relevant)
	}

	paths := make([]Path, 0)
	for _, startIdx := range starts {
		g.collectPathsTo(startIdx, targetIdx, relevant, nil, map[int]struct{}{}, &paths)
	}

	sort.Slice(paths, func(i, j int) bool {
		return pathNodesKey(paths[i].Nodes) < pathNodesKey(paths[j].Nodes)
	})
	return paths, nil
}

// TopologicalSort returns a topological ordering for the acyclic portion of the
// graph. If cycles remain, the returned slice contains the ordered prefix and
// ErrCycleDetected.
func (g *Graph) TopologicalSort() ([]GraphNode, error) {
	inDeg := make([]int, len(g.nodes))
	ready := &idIndexHeap{g: g, items: make([]int, 0, g.size)}
	for idx, node := range g.nodes {
		if node == nil || !g.alive[idx] {
			continue
		}
		inDeg[idx] = len(g.incoming[idx])
		if inDeg[idx] == 0 {
			heap.Push(ready, idx)
		}
	}

	ordered := make([]GraphNode, 0, g.size)
	for ready.Len() > 0 {
		idx := heap.Pop(ready).(int)
		ordered = append(ordered, g.nodes[idx])
		for childIdx := range g.outgoing[idx] {
			inDeg[childIdx]--
			if inDeg[childIdx] == 0 {
				heap.Push(ready, childIdx)
			}
		}
	}

	if len(ordered) != g.size {
		return ordered, ErrCycleDetected
	}
	return ordered, nil
}

// Size returns the number of nodes in the graph.
func (g *Graph) Size() int {
	return g.size
}

// WalkNodes iterates all live nodes. Returning false from fn stops iteration.
func (g *Graph) WalkNodes(fn func(GraphNode) bool) {
	if fn == nil {
		return
	}
	for idx, node := range g.nodes {
		if node == nil || !g.alive[idx] {
			continue
		}
		if !fn(node) {
			return
		}
	}
}

// WalkDependencyNodes iterates all live dependency nodes. Returning false
// from fn stops iteration.
func (g *Graph) WalkDependencyNodes(fn func(*DependencyNode) bool) {
	if fn == nil {
		return
	}
	g.WalkNodes(func(node GraphNode) bool {
		dep, ok := node.(*DependencyNode)
		if !ok {
			return true
		}
		return fn(dep)
	})
}

// WalkEdges iterates all dependency relationships (from -> to). Returning false
// stops iteration.
func (g *Graph) WalkEdges(fn func(from, to GraphNode) bool) {
	if fn == nil {
		return
	}
	for fromIdx, relationships := range g.outgoing {
		if !g.alive[fromIdx] || relationships == nil {
			continue
		}
		for toIdx := range relationships {
			if !g.alive[toIdx] {
				continue
			}
			if !fn(g.nodes[fromIdx], g.nodes[toIdx]) {
				return
			}
		}
	}
}

// PrettyString returns a stable, human-readable adjacency list.
func (g *Graph) PrettyString() string {
	if g.size == 0 {
		return "(empty graph)"
	}

	nodes := g.Nodes()
	var b strings.Builder
	for i, node := range nodes {
		deps, _ := g.DirectDependencies(node.NodeID())
		b.WriteString(node.NodeID())
		b.WriteString(" -> [")
		for j, dep := range deps {
			if j > 0 {
				b.WriteString(", ")
			}
			b.WriteString(dep.NodeID())
		}
		b.WriteString("]")
		if i < len(nodes)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// PrettyTree returns an ASCII tree view of dependencies from graph roots.
func (g *Graph) PrettyTree() string {
	if g.size == 0 {
		return "(empty graph)"
	}

	roots := g.Roots()
	if len(roots) == 0 {
		roots = g.Nodes()
	}

	expanded := make(map[int]struct{}, g.size)
	var b strings.Builder
	for _, root := range roots {
		rootIdx := g.indexByID[root.NodeID()]
		b.WriteString(nodeDisplayLabel(root))
		b.WriteByte('\n')
		expanded[rootIdx] = struct{}{}
		onPath := map[int]struct{}{rootIdx: {}}
		g.writeTree(&b, rootIdx, "", expanded, onPath)
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// Compare returns added, removed, version-changed, and detail-changed
// dependencies between base and head. Only dependency nodes participate:
// manifest and module nodes are structural.
func Compare(base, head *Graph) Diff {
	baseExact, headExact := indexDiffableNodes(base), indexDiffableNodes(head)
	baseRelationships := dependencyRelationshipsForGraph(base)
	headRelationships := dependencyRelationshipsForGraph(head)
	baseRemainder := make(map[string]*DependencyNode)
	headRemainder := make(map[string]*DependencyNode)
	transitions := make([]DependencyDetailTransition, 0)

	for id, node := range baseExact {
		if headNode, ok := headExact[id]; ok {
			if transition, changed := compareDependencyDetails(node, headNode, baseRelationships, headRelationships); changed {
				transitions = append(transitions, transition)
			}
			continue
		}
		baseRemainder[id] = node
	}
	for id, node := range headExact {
		if _, ok := baseExact[id]; ok {
			continue
		}
		headRemainder[id] = node
	}

	baseByIdentity := groupNodesByIdentity(baseRemainder)
	headByIdentity := groupNodesByIdentity(headRemainder)
	identities := make(map[string]struct{}, len(baseByIdentity)+len(headByIdentity))
	for key := range baseByIdentity {
		identities[key] = struct{}{}
	}
	for key := range headByIdentity {
		identities[key] = struct{}{}
	}

	diff := Diff{
		Added:       make([]*DependencyNode, 0),
		Removed:     make([]*DependencyNode, 0),
		Updated:     make([]VersionChange, 0),
		Transitions: transitions,
	}
	for key := range identities {
		baseNodes := baseByIdentity[key]
		headNodes := headByIdentity[key]
		sortNodesForDiff(baseNodes)
		sortNodesForDiff(headNodes)

		pairs := len(baseNodes)
		if len(headNodes) < pairs {
			pairs = len(headNodes)
		}
		for i := 0; i < pairs; i++ {
			before := baseNodes[i]
			after := headNodes[i]
			diff.Updated = append(diff.Updated, VersionChange{Before: before, After: after})
			if transition, changed := compareDependencyDetails(before, after, baseRelationships, headRelationships); changed {
				diff.Transitions = append(diff.Transitions, transition)
			}
		}
		if pairs < len(baseNodes) {
			diff.Removed = append(diff.Removed, baseNodes[pairs:]...)
		}
		if pairs < len(headNodes) {
			diff.Added = append(diff.Added, headNodes[pairs:]...)
		}
	}

	sortNodesForDiff(diff.Added)
	sortNodesForDiff(diff.Removed)
	sort.Slice(diff.Updated, func(i, j int) bool {
		left := diff.Updated[i]
		right := diff.Updated[j]
		if lk, rk := diffIdentityKey(left.Before), diffIdentityKey(right.Before); lk != rk {
			return lk < rk
		}
		if left.Before.Version != right.Before.Version {
			return left.Before.Version < right.Before.Version
		}
		if left.After.Version != right.After.Version {
			return left.After.Version < right.After.Version
		}
		return left.Before.NodeID() < right.Before.NodeID()
	})
	SortDependencyDetailTransitions(diff.Transitions)
	return diff
}

// CompareDependencyDetails returns a transition when relationship, source, or
// registry-matching eligibility differs between two dependency records. It is
// exported so trusted fuzzy identity reconciliation can use the same canonical
// classifier as Compare.
func CompareDependencyDetails(baseGraph, headGraph *Graph, before, after *DependencyNode) (DependencyDetailTransition, bool) {
	return compareDependencyDetails(
		before,
		after,
		dependencyRelationshipsForGraph(baseGraph),
		dependencyRelationshipsForGraph(headGraph),
	)
}

func compareDependencyDetails(before, after *DependencyNode, beforeRelationships, afterRelationships map[string]DependencyRelationship) (DependencyDetailTransition, bool) {
	if before == nil || after == nil {
		return DependencyDetailTransition{}, false
	}
	beforeRelationship := dependencyRelationshipFromMap(beforeRelationships, before)
	afterRelationship := dependencyRelationshipFromMap(afterRelationships, after)
	beforeEligible := before.RegistryMatchEligible()
	afterEligible := after.RegistryMatchEligible()
	changedFields := make([]DependencyDetailField, 0, 3)
	if beforeRelationship != DependencyRelationshipUnknown &&
		afterRelationship != DependencyRelationshipUnknown &&
		beforeRelationship != afterRelationship {
		changedFields = append(changedFields, DependencyDetailRelationship)
	}
	if before.Source != "" && after.Source != "" && before.Source != after.Source {
		changedFields = append(changedFields, DependencyDetailSource)
	}
	eligibilityEvidenceComparable := before.Source == after.Source || (before.Source != "" && after.Source != "")
	if eligibilityEvidenceComparable && beforeEligible != afterEligible {
		changedFields = append(changedFields, DependencyDetailRegistryEligibility)
	}
	if len(changedFields) == 0 {
		return DependencyDetailTransition{}, false
	}
	return DependencyDetailTransition{
		Before:                 before,
		After:                  after,
		ChangedFields:          changedFields,
		BeforeRelationship:     beforeRelationship,
		AfterRelationship:      afterRelationship,
		BeforeRegistryEligible: beforeEligible,
		AfterRegistryEligible:  afterEligible,
	}, true
}

func dependencyRelationshipFromMap(relationships map[string]DependencyRelationship, node *DependencyNode) DependencyRelationship {
	if node == nil {
		return DependencyRelationshipUnknown
	}
	if relationship := relationships[node.NodeID()]; relationship != "" {
		return relationship
	}
	return relationshipForDepth(node, 0)
}

func dependencyRelationshipsForGraph(graph *Graph) map[string]DependencyRelationship {
	relationships := make(map[string]DependencyRelationship)
	if graph == nil || graph.Size() == 0 {
		return relationships
	}
	roots := graph.Roots()
	hasUsableEdges := len(roots) > 0 && len(roots) != graph.Size()
	// A dependency is direct when it hangs off a root, or off a structural
	// node the traversal reached without passing through a dependency:
	// manifest and module nodes are not dependency hops, so
	// manifest → module → dependency is direct, while a dependency's own
	// structural descendant does not reset the depth beneath it.
	direct := make(map[int]struct{})
	if hasUsableEdges {
		owners := make([]int, 0, len(roots))
		seen := make(map[int]struct{}, len(roots))
		for _, root := range roots {
			if index, ok := graph.indexByID[root.NodeID()]; ok {
				if _, dup := seen[index]; !dup {
					seen[index] = struct{}{}
					owners = append(owners, index)
				}
			}
		}
		for cursor := 0; cursor < len(owners); cursor++ {
			ownerIndex := owners[cursor]
			for childIndex := range graph.outgoing[ownerIndex] {
				direct[childIndex] = struct{}{}
				child := graph.nodes[childIndex]
				if child == nil || !graph.alive[childIndex] {
					continue
				}
				if _, isDependency := child.(*DependencyNode); isDependency {
					continue
				}
				if _, dup := seen[childIndex]; dup {
					continue
				}
				seen[childIndex] = struct{}{}
				owners = append(owners, childIndex)
			}
		}
	}

	for index, node := range graph.nodes {
		if node == nil || !graph.alive[index] {
			continue
		}
		dep, ok := node.(*DependencyNode)
		if !ok {
			continue
		}
		if dep.Relationship != "" {
			relationships[dep.NodeID()] = relationshipForDepth(dep, 0)
			continue
		}
		depth := 0
		if hasUsableEdges && len(graph.incoming[index]) > 0 {
			depth = 2
			if _, ok := direct[index]; ok {
				depth = 1
			}
		}
		relationships[dep.NodeID()] = relationshipForDepth(dep, depth)
	}
	return relationships
}

// SortDependencyDetailTransitions orders detail changes deterministically.
func SortDependencyDetailTransitions(transitions []DependencyDetailTransition) {
	sort.Slice(transitions, func(i, j int) bool {
		left := transitions[i]
		right := transitions[j]
		if lk, rk := diffIdentityKey(left.Before), diffIdentityKey(right.Before); lk != rk {
			return lk < rk
		}
		if left.Before.Version != right.Before.Version {
			return left.Before.Version < right.Before.Version
		}
		if left.After.Version != right.After.Version {
			return left.After.Version < right.After.Version
		}
		if left.Before.NodeID() != right.Before.NodeID() {
			return left.Before.NodeID() < right.Before.NodeID()
		}
		return left.After.NodeID() < right.After.NodeID()
	})
}

func indexDiffableNodes(g *Graph) map[string]*DependencyNode {
	indexed := make(map[string]*DependencyNode)
	if g == nil {
		return indexed
	}
	g.WalkDependencyNodes(func(node *DependencyNode) bool {
		indexed[node.NodeID()] = node
		return true
	})
	return indexed
}

// diffIdentityKey is the version-less grouping key for version-change
// detection: the canonical package URL with its version stripped and its
// qualifiers kept, so two architectures of one package never read as a
// version pair.
func diffIdentityKey(node *DependencyNode) string {
	if node == nil {
		return ""
	}
	if key := purlkit.WithoutVersion(node.NodeID()); key != "" {
		return key
	}
	return node.NodeID()
}

func groupNodesByIdentity(nodes map[string]*DependencyNode) map[string][]*DependencyNode {
	grouped := make(map[string][]*DependencyNode)
	for _, node := range nodes {
		key := diffIdentityKey(node)
		grouped[key] = append(grouped[key], node)
	}
	return grouped
}

func sortNodesForDiff(nodes []*DependencyNode) {
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Version != nodes[j].Version {
			return nodes[i].Version < nodes[j].Version
		}
		return nodes[i].NodeID() < nodes[j].NodeID()
	})
}

func (g *Graph) lookupSorted(ids map[int]struct{}) []GraphNode {
	indices := make([]int, 0, len(ids))
	for idx := range ids {
		indices = append(indices, idx)
	}
	sort.Slice(indices, func(i, j int) bool {
		return g.nodes[indices[i]].NodeID() < g.nodes[indices[j]].NodeID()
	})

	out := make([]GraphNode, 0, len(indices))
	for _, idx := range indices {
		out = append(out, g.nodes[idx])
	}
	return out
}

func (g *Graph) writeTree(b *strings.Builder, nodeIdx int, prefix string, expanded map[int]struct{}, onPath map[int]struct{}) {
	children := g.sortedAdjacent(g.outgoing[nodeIdx])
	for i, childIdx := range children {
		isLast := i == len(children)-1
		b.WriteString(prefix)
		if isLast {
			b.WriteString("`-- ")
		} else {
			b.WriteString("|-- ")
		}
		b.WriteString(nodeDisplayLabel(g.nodes[childIdx]))

		if _, seen := onPath[childIdx]; seen {
			b.WriteString(" (cycle)\n")
			continue
		}
		if _, seen := expanded[childIdx]; seen {
			b.WriteString(" (shared)\n")
			continue
		}

		b.WriteByte('\n')
		expanded[childIdx] = struct{}{}
		onPath[childIdx] = struct{}{}
		nextPrefix := prefix
		if isLast {
			nextPrefix += "    "
		} else {
			nextPrefix += "|   "
		}
		g.writeTree(b, childIdx, nextPrefix, expanded, onPath)
		delete(onPath, childIdx)
	}
}

func nodeDisplayLabel(node GraphNode) string {
	if node == nil {
		return ""
	}
	dep, ok := node.(*DependencyNode)
	if !ok {
		return node.NodeID()
	}
	label := dep.NodeID()
	scope := dep.PrimaryScope()
	if scope == ScopeUnknown {
		return label
	}
	return label + " [" + string(scope) + "]"
}

func (g *Graph) collectPathsTo(currentIdx, targetIdx int, relevant map[int]struct{}, stack []int, active map[int]struct{}, paths *[]Path) {
	if _, ok := relevant[currentIdx]; !ok {
		return
	}
	if _, seen := active[currentIdx]; seen {
		return
	}

	stack = append(stack, currentIdx)
	active[currentIdx] = struct{}{}
	defer delete(active, currentIdx)

	if currentIdx == targetIdx {
		*paths = append(*paths, g.buildPath(stack, false, ""))
	}

	for _, childIdx := range g.sortedAdjacent(g.outgoing[currentIdx]) {
		if _, ok := relevant[childIdx]; !ok {
			continue
		}
		if _, seen := active[childIdx]; seen {
			if childIdx == targetIdx {
				cycleStack := append(append([]int(nil), stack...), childIdx)
				*paths = append(*paths, g.buildPath(cycleStack, true, g.nodes[childIdx].NodeID()))
			}
			continue
		}
		g.collectPathsTo(childIdx, targetIdx, relevant, stack, active, paths)
	}
}

func (g *Graph) buildPath(indices []int, cyclic bool, cycleTo string) Path {
	nodes := make([]GraphNode, 0, len(indices))
	for _, idx := range indices {
		nodes = append(nodes, g.nodes[idx])
	}
	return Path{
		Nodes:   nodes,
		Cyclic:  cyclic,
		CycleTo: cycleTo,
	}
}

func (g *Graph) reverseReachable(startIdx int) map[int]struct{} {
	reachable := map[int]struct{}{startIdx: {}}
	stack := []int{startIdx}
	for len(stack) > 0 {
		idx := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for parentIdx := range g.incoming[idx] {
			if _, seen := reachable[parentIdx]; seen {
				continue
			}
			reachable[parentIdx] = struct{}{}
			stack = append(stack, parentIdx)
		}
	}
	return reachable
}

func (g *Graph) relevantRoots(relevant map[int]struct{}) []int {
	roots := make([]int, 0, len(relevant))
	for _, idx := range g.sortedRelevantIndices(relevant) {
		hasRelevantParent := false
		for parentIdx := range g.incoming[idx] {
			if _, ok := relevant[parentIdx]; ok {
				hasRelevantParent = true
				break
			}
		}
		if !hasRelevantParent {
			roots = append(roots, idx)
		}
	}
	return roots
}

func (g *Graph) sortedRelevantIndices(relevant map[int]struct{}) []int {
	indices := make([]int, 0, len(relevant))
	for idx := range relevant {
		indices = append(indices, idx)
	}
	sort.Slice(indices, func(i, j int) bool {
		return g.nodes[indices[i]].NodeID() < g.nodes[indices[j]].NodeID()
	})
	return indices
}

func pathNodesKey(nodes []GraphNode) string {
	ids := make([]string, 0, len(nodes))
	for _, node := range nodes {
		ids = append(ids, node.NodeID())
	}
	return strings.Join(ids, "/")
}

func (g *Graph) sortedAdjacent(adj map[int]struct{}) []int {
	indices := make([]int, 0, len(adj))
	for idx := range adj {
		indices = append(indices, idx)
	}
	sort.Slice(indices, func(i, j int) bool {
		return g.nodes[indices[i]].NodeID() < g.nodes[indices[j]].NodeID()
	})
	return indices
}

func (g *Graph) sortedIndices() []int {
	indices := make([]int, 0, g.size)
	for _, idx := range g.indexByID {
		indices = append(indices, idx)
	}
	sort.Slice(indices, func(i, j int) bool {
		return g.nodes[indices[i]].NodeID() < g.nodes[indices[j]].NodeID()
	})
	return indices
}

func (g *Graph) requireIndex(id string) (int, error) {
	idx, ok := g.indexByID[id]
	if !ok {
		return 0, fmt.Errorf("%w: %s", ErrNodeNotFound, id)
	}
	return idx, nil
}

func (g *Graph) nextSlot() int {
	if n := len(g.free); n > 0 {
		idx := g.free[n-1]
		g.free = g.free[:n-1]
		return idx
	}

	g.nodes = append(g.nodes, nil)
	g.alive = append(g.alive, false)
	g.outgoing = append(g.outgoing, nil)
	g.incoming = append(g.incoming, nil)
	return len(g.nodes) - 1
}

type idIndexHeap struct {
	g     *Graph
	items []int
}

func (h *idIndexHeap) Len() int {
	return len(h.items)
}

func (h *idIndexHeap) Less(i, j int) bool {
	return h.g.nodes[h.items[i]].NodeID() < h.g.nodes[h.items[j]].NodeID()
}

func (h *idIndexHeap) Swap(i, j int) {
	h.items[i], h.items[j] = h.items[j], h.items[i]
}

func (h *idIndexHeap) Push(x any) {
	h.items = append(h.items, x.(int))
}

func (h *idIndexHeap) Pop() any {
	old := h.items
	n := len(old)
	x := old[n-1]
	h.items = old[:n-1]
	return x
}
