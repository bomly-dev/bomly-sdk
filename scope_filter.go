package sdk

import "fmt"

// FilterGraphByScope returns a graph view containing roots plus dependencies
// whose normalized scope matches the requested filter.
func FilterGraphByScope(src *Graph, scope Scope) (*Graph, error) {
	if src == nil || scope == ScopeUnknown {
		return src, nil
	}

	// Manifest and module nodes are structural and are always retained;
	// scope filtering applies to dependency nodes only, and only
	// structural nodes are retained unconditionally. Seeding from
	// Roots() would disable filtering entirely for an edgeless graph (every
	// node is a root there) and would retain any orphan dependency
	// regardless of scope — a caller asking for runtime would receive
	// development dependencies too.
	allowed := make(map[string]struct{}, src.Size())
	src.WalkNodes(func(node GraphNode) bool {
		switch n := node.(type) {
		case *DependencyNode:
			if n.PrimaryScope() == scope {
				allowed[n.NodeID()] = struct{}{}
			}
		default:
			allowed[node.NodeID()] = struct{}{}
		}
		return true
	})

	filtered := NewWithCapacity(len(allowed))
	for id := range allowed {
		node, ok := src.Node(id)
		if !ok {
			continue
		}
		if err := filtered.AddNode(node.CloneNode()); err != nil {
			return nil, err
		}
	}

	var mergeErr error
	// Through the shared primitive, so a kept edge keeps its kind. Renaming
	// to "" is how an edge touching a dropped node is omitted.
	keep := func(id string) string {
		if _, ok := allowed[id]; !ok {
			return ""
		}
		return id
	}
	if err := CopyEdgesInto(filtered, src, keep); err != nil {
		mergeErr = fmt.Errorf("add filtered edge: %w", err)
	}
	if mergeErr != nil {
		return nil, mergeErr
	}

	return filtered, nil
}

// FilterDetectionResultByScope applies scope filtering to each graph entry in a
// detector result.
func FilterDetectionResultByScope(result DetectionResult, scope Scope) (DetectionResult, error) {
	if scope == ScopeUnknown || result.Graphs == nil {
		return result, nil
	}
	entries := make([]GraphEntry, 0, len(result.Graphs.Entries))
	for _, entry := range result.Graphs.Entries {
		if entry.Graph == nil {
			entries = append(entries, entry)
			continue
		}
		graphView, err := FilterGraphByScope(entry.Graph, scope)
		if err != nil {
			return DetectionResult{}, err
		}
		entry.Graph = graphView
		entry.Packages = filterEntryPackagesByGraph(entry.Packages, graphView)
		entries = append(entries, entry)
	}
	result.Graphs = &GraphContainer{Entries: entries}
	return result, nil
}

func filterEntryPackagesByGraph(packages []*Package, graph *Graph) []*Package {
	if len(packages) == 0 || graph == nil {
		return packages
	}
	allowed := make(map[string]struct{}, graph.Size())
	graph.WalkDependencyNodes(func(dep *DependencyNode) bool {
		allowed[dep.NodeID()] = struct{}{}
		return true
	})
	if len(allowed) == 0 {
		return nil
	}
	filtered := make([]*Package, 0, len(packages))
	for _, pkg := range packages {
		if pkg == nil {
			continue
		}
		if _, ok := allowed[pkg.PURL]; ok {
			filtered = append(filtered, pkg)
		}
	}
	return filtered
}
