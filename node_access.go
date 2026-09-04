package sdk

// Reading a node of any kind.
//
// GraphNode deliberately exposes only what every kind has: an ID, a kind,
// locations, warnings, a clone. Everything else -- coordinates, a display
// name, a scope -- belongs to some kinds and not others, so without an
// accessor here every consumer writes the same type switch.
//
// Written once per consumer, that switch disagrees with itself: one copy
// treats a manifest as an empty package, another as a package with no name,
// a third forgets the kind exists and dereferences a nil. The CLI grew four
// such copies within a single release; these are the one place that decides
// what each kind looks like to a reader.

// NodeCoordinates returns the package coordinates a node carries, and reports
// whether it carries any.
//
// A manifest node does not: a file is not a package. A typed nil does not
// either, which is why the check is here rather than at each call site --
// comparing a GraphNode against nil is false for a (*DependencyNode)(nil),
// and the next field read panics.
func NodeCoordinates(node GraphNode) (Coordinates, bool) {
	switch typed := node.(type) {
	case *DependencyNode:
		if typed == nil {
			return Coordinates{}, false
		}
		return typed.Coordinates, true
	case *ModuleNode:
		if typed == nil {
			return Coordinates{}, false
		}
		return typed.Coordinates, true
	default:
		return Coordinates{}, false
	}
}

// NodeDisplayName returns the name a node shows under: the ecosystem-native
// display name for a node with coordinates, and the path for a manifest,
// which is the only name a manifest has.
func NodeDisplayName(node GraphNode) string {
	if manifest, ok := node.(*ManifestNode); ok && manifest != nil {
		return manifest.Path
	}
	coords, ok := NodeCoordinates(node)
	if !ok {
		return ""
	}
	return coords.DisplayName()
}

// NodeVersion returns the version a node carries, or "" when it carries none.
func NodeVersion(node GraphNode) string {
	coords, ok := NodeCoordinates(node)
	if !ok {
		return ""
	}
	return coords.Version
}

// AsDependencyNode narrows a node to a dependency node, reporting whether it
// is one. A typed nil is not.
func AsDependencyNode(node GraphNode) (*DependencyNode, bool) {
	dep, ok := node.(*DependencyNode)
	return dep, ok && dep != nil
}

// AsModuleNode narrows a node to a module node, reporting whether it is one.
func AsModuleNode(node GraphNode) (*ModuleNode, bool) {
	module, ok := node.(*ModuleNode)
	return module, ok && module != nil
}

// DependencyNodesOf narrows a slice of graph nodes to the dependency nodes
// among them.
//
// Graph traversal yields the union -- DirectDependencies, Dependents, Roots,
// Leaves -- and most logic over the result is about consumed packages
// specifically: scope propagation, relationship marking, enrichment.
// Narrowing in one named place keeps every site agreeing about what a
// structural node means there: it is skipped, not defaulted.
func DependencyNodesOf(list []GraphNode) []*DependencyNode {
	out := make([]*DependencyNode, 0, len(list))
	for _, node := range list {
		if dep, ok := AsDependencyNode(node); ok {
			out = append(out, dep)
		}
	}
	return out
}

// IsProjectOwned reports whether a node stands for the scanned project's own
// code -- its root package, a workspace member, a reactor module -- rather
// than a package it consumes.
//
// It reads the node kind. ADR-0041 removed the FirstParty flag because
// ownership is what the kind means: the project's own artifacts are module
// nodes, and a dependency node is a consumed package by construction. The
// application package type is not sufficient on its own -- an
// application-typed *import* is a consumed package, and treating it as owned
// is what kept such packages out of diffing and matching.
func IsProjectOwned(node GraphNode) bool {
	if IsNilNode(node) {
		return false
	}
	return node.Kind() == NodeKindModule
}

// IsNilNode reports whether a node value carries no node, a typed nil
// included.
//
// A typed nil is not an untyped one: comparing the interface against nil is
// false for a (*DependencyNode)(nil), and the next method call dereferences
// it. Every helper that accepts a GraphNode from a caller's slice needs this,
// so it is exported rather than repeated.
func IsNilNode(node GraphNode) bool {
	switch typed := node.(type) {
	case nil:
		return true
	case *DependencyNode:
		return typed == nil
	case *ModuleNode:
		return typed == nil
	case *ManifestNode:
		return typed == nil
	default:
		return false
	}
}
