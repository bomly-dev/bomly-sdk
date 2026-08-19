package matcherkit

import sdk "github.com/bomly-dev/bomly-sdk"

// RegistryPackagesForGraph seeds the PURL-keyed package registry from the
// dependency graph and returns the registry packages that matchers should
// enrich. Each dependency node is linked to its package via PackageRef (PURL);
// packages are deduplicated by PURL so a matcher enriches each unique package
// once regardless of how many dependency instances reference it. First-party
// nodes (sdk.NodeIsEnrichable is false) are never returned: they are absent
// from external sources, and querying them risks coincidental name matches.
//
// When a target is set, only the target dependency is considered.
func RegistryPackagesForGraph(g *sdk.Graph, reg *sdk.PackageRegistry, target *sdk.Dependency) []*sdk.Package {
	if g == nil || reg == nil {
		return nil
	}

	deps := g.Nodes()
	if target != nil {
		deps = []*sdk.Dependency{target}
	}

	seen := make(map[string]struct{}, len(deps))
	out := make([]*sdk.Package, 0, len(deps))
	for _, dep := range deps {
		if !sdk.NodeIsEnrichable(dep) {
			continue
		}
		purl := sdk.CanonicalPackageURLFromDependency(dep)
		if purl == "" {
			continue
		}
		dep.PackageRef = purl

		pkg, ok := reg.Get(purl)
		if !ok {
			pkg = reg.Add(sdk.PackageFromDependency(dep))
		} else if pkg != nil {
			// A package is enriched once, but every occurrence of it still
			// gets a say about where it came from: two manifests resolving
			// one package from different places disagree, and the package
			// must not report whichever was walked first.
			pkg.Origin = sdk.ReconcileOrigin(pkg.Origin, dep.Origin)
		}

		if _, alreadySeen := seen[purl]; alreadySeen {
			continue
		}
		seen[purl] = struct{}{}
		if pkg != nil {
			out = append(out, pkg)
		}
	}
	return out
}
