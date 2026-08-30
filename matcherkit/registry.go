package matcherkit

import sdk "github.com/bomly-dev/bomly-sdk"

// RegistryPackagesForGraph seeds the PURL-keyed package registry from the
// graph's dependency nodes and returns the registry packages that matchers
// should enrich. Under the typed union only dependency nodes exist to
// matching — module and manifest nodes are structural and never reach
// external sources — and a dependency node's ID is its canonical package
// URL, so PackageRef is set to it directly. Packages are deduplicated by
// PURL so a matcher enriches each unique package once regardless of how
// many dependency records reference it.
//
// When a target is set, only the target dependency is considered.
func RegistryPackagesForGraph(g *sdk.Graph, reg *sdk.PackageRegistry, target *sdk.DependencyNode) []*sdk.Package {
	if g == nil || reg == nil {
		return nil
	}

	deps := g.DependencyNodes()
	if target != nil {
		deps = []*sdk.DependencyNode{target}
	}

	seen := make(map[string]struct{}, len(deps))
	out := make([]*sdk.Package, 0, len(deps))
	for _, dep := range deps {
		if dep == nil {
			continue
		}
		purl := dep.NodeID()
		dep.PackageRef = purl

		if _, alreadySeen := seen[purl]; alreadySeen {
			continue
		}
		seen[purl] = struct{}{}

		// Always seed through Add: it merges into an existing record rather
		// than replacing it, so a package the registry already holds (from
		// GraphEntry.Packages, say) still receives this node's detected
		// origins — the repository signal that replaced the URL-valued purl
		// qualifiers.
		pkg := reg.Add(sdk.PackageFromDependencyNode(dep))
		if pkg != nil {
			out = append(out, pkg)
		}
	}
	return out
}
