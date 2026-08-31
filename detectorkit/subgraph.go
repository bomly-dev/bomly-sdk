package detectorkit

import (
	"errors"
	"fmt"

	sdk "github.com/bomly-dev/bomly-sdk"
)

// SubgraphFrom returns a new graph containing rootID and every node and edge
// reachable from it in g. Detectors that resolve a whole workspace/reactor
// into one graph use it to partition the merged graph into per-module
// manifest entries: each module entry carries the module root plus its
// reachable dependency subtree. Node pointers are shared with the source
// graph, matching how detectors already share nodes across container entries.
func SubgraphFrom(g *sdk.Graph, rootID string) (*sdk.Graph, error) {
	if g == nil {
		return nil, errors.New("subgraph from nil graph")
	}
	root, ok := g.Node(rootID)
	if !ok {
		return nil, fmt.Errorf("subgraph root %q not found in graph", rootID)
	}

	out := sdk.New()
	visited := map[string]struct{}{}
	var walk func(pkg sdk.GraphNode) error
	walk = func(pkg sdk.GraphNode) error {
		if pkg == nil {
			return nil
		}
		if _, ok := visited[pkg.NodeID()]; ok {
			return nil
		}
		visited[pkg.NodeID()] = struct{}{}
		if err := out.AddNode(pkg); err != nil {
			return fmt.Errorf("add subgraph node %q: %w", pkg.NodeID(), err)
		}
		deps, err := g.DirectDependencies(pkg.NodeID())
		if err != nil {
			return fmt.Errorf("subgraph dependencies of %q: %w", pkg.NodeID(), err)
		}
		for _, dep := range deps {
			if dep == nil {
				continue
			}
			if err := walk(dep); err != nil {
				return err
			}
			// Typed rather than bare: this rebuilds a graph, and the kind the
			// source graph recorded is the one the subgraph must carry.
			kind := g.EdgeKindOf(pkg.NodeID(), dep.NodeID())
			if err := out.AddTypedEdge(pkg.NodeID(), dep.NodeID(), kind); err != nil && !errors.Is(err, sdk.ErrSelfDependency) {
				return fmt.Errorf("add subgraph edge %q -> %q: %w", pkg.NodeID(), dep.NodeID(), err)
			}
		}
		return nil
	}
	if err := walk(root); err != nil {
		return nil, err
	}
	return out, nil
}
