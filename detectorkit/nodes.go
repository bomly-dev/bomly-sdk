package detectorkit

import (
	"errors"
	"fmt"
	"strings"

	sdk "github.com/bomly-dev/bomly-sdk"
)

// EnsureNode inserts a node into a graph, or returns the node already
// carrying its identity.
//
// Every detector needs this: a lockfile can name one package more than once,
// and a graph keeps one node per identity. Doing the existence check by hand
// is what left a dozen detectors silently discarding a duplicate record's
// data -- each copy of the check written independently, each deciding
// differently what to do with the loser.
//
// The fold itself is Graph.InsertNode's: scopes, locations, and origins union
// onto the survivor. This adds the typed return and the nil tolerance callers
// rely on, so a detector inserting a module gets a module back without
// asserting. A survivor of a different kind is an error rather than a silent
// nil: two nodes sharing one ID across kinds means the ID grammars collided,
// and a detector must not carry on with a node that is not what it built.
func EnsureNode[T sdk.GraphNode](g *sdk.Graph, node T) (T, error) {
	var zero T
	if g == nil || sdk.IsNilNode(node) {
		return zero, nil
	}
	inserted, err := g.InsertNode(node)
	if err != nil {
		return zero, fmt.Errorf("add node %q: %w", node.NodeID(), err)
	}
	surviving, ok := inserted.(T)
	if !ok {
		return zero, fmt.Errorf("node %q already exists as a %s node", node.NodeID(), inserted.Kind())
	}
	return surviving, nil
}

// PromoteToModule replaces a node with a module node declared by a manifest
// path, keeping its edges, and returns the surviving node's ID.
//
// A node's kind and identity are both fixed at construction, so a detector
// that only learns ownership later cannot set a flag or rewrite an ID
// afterwards. Maven learns which graph roots are reactor modules after
// parsing the dependency tree, and which directory declares each one later
// still; Cargo learns a member's directory only once the metadata's absolute
// manifest paths can be made relative to the scan. Both replace the node, and
// this is the one place that knows how: build the module, re-point every
// edge, remove the old node.
//
// It is idempotent for the path it is given: a module already declared by
// that manifest is returned unchanged, and one declared by another manifest
// is re-minted, because the declaring path is part of a module's identity.
//
// Edges are re-added by ID, so callers must not hold node pointers across the
// call; the returned ID is what to hold instead.
func PromoteToModule(g *sdk.Graph, nodeID, manifestPath string) (string, error) {
	if g == nil || strings.TrimSpace(nodeID) == "" {
		return nodeID, nil
	}
	existing, ok := g.Node(nodeID)
	if !ok {
		return nodeID, nil
	}

	var locations []sdk.PackageLocation
	switch typed := existing.(type) {
	case *sdk.DependencyNode:
		locations = typed.Locations
	case *sdk.ModuleNode:
		if typed.DeclaringManifestPath == manifestPath {
			return nodeID, nil
		}
		locations = typed.Locations
	default:
		// A manifest node is already structural and declares nothing.
		return nodeID, nil
	}
	coords, ok := sdk.NodeCoordinates(existing)
	if !ok {
		return nodeID, nil
	}

	module, err := sdk.NewModuleNode(manifestPath, coords)
	if err != nil {
		return nodeID, fmt.Errorf("promote %q to a module node: %w", nodeID, err)
	}
	if module.NodeID() == nodeID {
		return nodeID, nil
	}
	module.Locations = append([]sdk.PackageLocation(nil), locations...)

	parents, _ := g.Dependents(nodeID)
	children, _ := g.DirectDependencies(nodeID)
	parentIDs := make([]string, 0, len(parents))
	for _, parent := range parents {
		parentIDs = append(parentIDs, parent.NodeID())
	}
	childIDs := make([]string, 0, len(children))
	for _, child := range children {
		childIDs = append(childIDs, child.NodeID())
	}

	g.RemoveNode(nodeID)
	surviving, err := g.InsertNode(module)
	if err != nil {
		return nodeID, fmt.Errorf("insert promoted module %q: %w", module.NodeID(), err)
	}
	survivingID := surviving.NodeID()
	for _, parentID := range parentIDs {
		if err := reattach(g, parentID, survivingID); err != nil {
			return survivingID, err
		}
	}
	for _, childID := range childIDs {
		if err := reattach(g, survivingID, childID); err != nil {
			return survivingID, err
		}
	}
	return survivingID, nil
}

func reattach(g *sdk.Graph, fromID, toID string) error {
	if fromID == toID {
		return nil
	}
	if err := g.AddEdge(fromID, toID); err != nil && !errors.Is(err, sdk.ErrSelfDependency) {
		return fmt.Errorf("re-point %q -> %q: %w", fromID, toID, err)
	}
	return nil
}

// PropagateScopes seeds the scopes of a root's direct dependencies and
// spreads them breadth-first through the graph, so a package reachable on a
// runtime path is marked runtime even when it is also a development
// dependency. Any dependency node still unscoped afterwards defaults to
// runtime: a package the resolver installed is used at runtime unless
// something said otherwise.
//
// This lived three times over in one detector family, with the same
// termination trap in each copy -- a walk that revisits a node whose scope did
// not change never finishes on a cyclic graph. Only the seed differed, so
// that is the parameter: seed reports where a direct dependency starts, and a
// nil seed reads the node's own primary scope. Non-dependency nodes are
// skipped; scope is a claim about a consumed package, and a manifest or a
// module does not carry one.
func PropagateScopes(g *sdk.Graph, rootID string, seed func(*sdk.DependencyNode) sdk.Scope) {
	if g == nil {
		return
	}
	if seed == nil {
		seed = func(node *sdk.DependencyNode) sdk.Scope { return node.PrimaryScope() }
	}

	directNodes, _ := g.DirectDependencies(rootID)
	directDeps := sdk.DependencyNodesOf(directNodes)
	propagated := make(map[string]sdk.Scope, g.Size())
	queue := make([]*sdk.DependencyNode, 0, len(directDeps))
	for _, dep := range directDeps {
		scope := seed(dep)
		if scope == sdk.ScopeUnknown {
			scope = sdk.ScopeRuntime
		}
		propagated[dep.NodeID()] = sdk.MergeScope(propagated[dep.NodeID()], scope)
		dep.AddScope(propagated[dep.NodeID()])
		queue = append(queue, dep)
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		scope := propagated[current.NodeID()]
		if scope == sdk.ScopeUnknown {
			continue
		}
		children, err := g.DirectDependencies(current.NodeID())
		if err != nil {
			continue
		}
		for _, child := range sdk.DependencyNodesOf(children) {
			if child.NodeID() == rootID {
				continue
			}
			next := sdk.MergeScope(propagated[child.NodeID()], scope)
			// Stop when neither the propagated value nor the node's own scope
			// would change: without this the queue revisits every cycle
			// forever.
			if next == propagated[child.NodeID()] && child.PrimaryScope() == next {
				continue
			}
			propagated[child.NodeID()] = next
			child.AddScope(next)
			queue = append(queue, child)
		}
	}

	for _, pkg := range g.DependencyNodes() {
		if pkg != nil && pkg.NodeID() != rootID && pkg.PrimaryScope() == sdk.ScopeUnknown {
			pkg.AddScope(sdk.ScopeRuntime)
		}
	}
}
