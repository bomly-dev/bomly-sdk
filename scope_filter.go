package sdk

import (
	"fmt"
	"sort"
)

// A scope filter narrows a view to what a scope was asserted to be, and the
// hard case is a dependency no one asserted anything about. Nothing outside
// Bomly can answer it: no SBOM specification defines what "--scope runtime"
// returns, because the scope vocabulary being filtered is Bomly's own two
// values rather than any format's. So this is policy, recorded here rather
// than delegated.
//
// The policy is that a filter selects on assertions, and absence is not an
// assertion. A runtime view keeps everything not affirmatively
// development-only -- a set naming both scopes names runtime, so it stays --
// and every other view requires an affirmative match. That is one rule applied
// twice, not two rules: an unasserted scope resolves toward "may be in
// production", the only direction that cannot hide a finding. Dropping an
// unscoped dependency from a runtime view costs a missed vulnerability;
// keeping it costs a longer list. MergeScope already prefers runtime in a
// mixed set for the same reason.
//
// This matters far past an edge case. SPDX has no scope concept at all, so
// every package in a document Bomly did not write arrives unscoped, and the
// earlier rule -- match the effective scope exactly -- emptied a runtime view
// of such a document entirely.
//
// The rule belongs to the set, not to the ingest hop that produced it.
// CycloneDX ingest defaults an absent scalar to runtime because the CycloneDX
// specification instructs a consumer to; SPDX issues no such instruction, so
// stamping a scope onto an SPDX package would put a claim in the model that
// no document made, and it would round-trip back out into an exported
// document. The filter is where absence is answered.

// ScopeSetMatches reports whether a scope set belongs in a view narrowed to
// want. It is where the absence rule lives, so that the graph filter and the
// usage filter cannot drift apart on it.
//
// A runtime view keeps a set that names runtime, and also one that names
// nothing it can act on -- no scope at all, or only scopes this build cannot
// read, which is what a newer Bomly's token looks like here. Neither states
// that the dependency is outside what ships. Every other view matches by
// membership only, because a package that might ship must not appear in the
// list a user reads as the one they can deprioritize.
//
// The runtime arm is written as membership rather than as a test on the
// effective scope, and the two are not interchangeable: MergeScope folds any
// two non-runtime scopes to development, so a set holding two tokens this
// build cannot read -- neither of them development -- has a PrimaryScope of
// ScopeDevelopment, and an effective-scope test would drop it from a runtime
// view. That is this function's own failure mode arriving by another door.
//
// A want of ScopeUnknown is not a filter and matches everything, which is how
// a caller spells "no scope was requested".
func ScopeSetMatches(scopes []Scope, want Scope) bool {
	switch want {
	case ScopeUnknown:
		return true
	case ScopeRuntime:
		return containsScope(scopes, ScopeRuntime) || !containsScope(scopes, ScopeDevelopment)
	default:
		return containsScope(scopes, want)
	}
}

// MatchesScopeFilter reports whether the dependency belongs in a graph view
// narrowed to want.
//
// A runtime view is ScopeSetMatches: the absence rule is the same wherever a
// scope set is matched. Every other view additionally requires that the set
// not name runtime, because Scopes is a union across declaration sites: a
// package reached from a development root and from a runtime root ships, and
// listing it in a development view would present a shipping package as one to
// deprioritize. That is the one place this differs from matching a single
// site's scopes, where naming a scope is the whole question.
//
// The extra condition is spelled out rather than delegated to PrimaryScope,
// which cannot answer it: MergeScope's fall-through returns ScopeDevelopment
// for any two non-runtime scopes, so a set of two tokens this build cannot
// read has an effective scope of development and a comparison against it
// would put a dependency nobody scoped development into the very view that
// must be affirmative. Membership is what "affirmative" means here.
func (n *DependencyNode) MatchesScopeFilter(want Scope) bool {
	if n == nil {
		return false
	}
	if want == ScopeUnknown {
		return true
	}
	if want == ScopeRuntime {
		return ScopeSetMatches(n.Scopes, want)
	}
	return containsScope(n.Scopes, want) && !containsScope(n.Scopes, ScopeRuntime)
}

// keptOnAbsence reports whether a runtime view kept this dependency only
// because its scope set asserted nothing readable -- the case worth telling a
// user about, since the filter did not narrow anything there.
func (n *DependencyNode) keptOnAbsence(want Scope) bool {
	return want == ScopeRuntime && n != nil && !containsScope(n.Scopes, ScopeRuntime)
}

// ScopeFilterReport says what a scope filter could not narrow. The SDK does
// not log, so the count reaches a user only if the caller reports it: a
// runtime view that kept most of the graph on absence has told the user far
// less than the flag implied, and silence there reads as a filtered result.
type ScopeFilterReport struct {
	// Unasserted are the IDs of the dependency nodes a runtime view kept
	// because their scope set named nothing this build can read, sorted and
	// deduplicated. Empty for every other view, and for a runtime view over
	// a graph whose dependencies all stated a scope.
	Unasserted []string
}

// FilterGraphByScope returns a graph view containing roots plus dependencies
// whose scope matches the requested filter, per MatchesScopeFilter.
//
// It discards the report; a caller that wants to tell a user how much of a
// runtime view was kept on absence calls FilterGraphByScopeWithReport.
func FilterGraphByScope(src *Graph, scope Scope) (*Graph, error) {
	graph, _, err := FilterGraphByScopeWithReport(src, scope)
	return graph, err
}

// FilterGraphByScopeWithReport is FilterGraphByScope, and also says which
// dependencies a runtime view kept because they asserted no scope.
func FilterGraphByScopeWithReport(src *Graph, scope Scope) (*Graph, ScopeFilterReport, error) {
	var report ScopeFilterReport
	if src == nil || scope == ScopeUnknown {
		return src, report, nil
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
			if !n.MatchesScopeFilter(scope) {
				return true
			}
			allowed[n.NodeID()] = struct{}{}
			if n.keptOnAbsence(scope) {
				report.Unasserted = append(report.Unasserted, n.NodeID())
			}
		default:
			allowed[node.NodeID()] = struct{}{}
		}
		return true
	})
	sort.Strings(report.Unasserted)

	filtered := NewWithCapacity(len(allowed))
	for id := range allowed {
		node, ok := src.Node(id)
		if !ok {
			continue
		}
		if err := filtered.AddNode(node.CloneNode()); err != nil {
			return nil, report, err
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
		return nil, report, mergeErr
	}

	return filtered, report, nil
}

// FilterDetectionResultByScope applies scope filtering to each graph entry in a
// detector result, discarding the report.
func FilterDetectionResultByScope(result DetectionResult, scope Scope) (DetectionResult, error) {
	filtered, _, err := FilterDetectionResultByScopeWithReport(result, scope)
	return filtered, err
}

// FilterDetectionResultByScopeWithReport is FilterDetectionResultByScope, and
// also says which dependencies a runtime view kept across every entry because
// they asserted no scope. This is the variant a pipeline calls: it is the one
// hop that sees the whole result, so it is where a user-facing warning about
// how much the filter could not narrow can be raised once rather than per
// entry.
func FilterDetectionResultByScopeWithReport(result DetectionResult, scope Scope) (DetectionResult, ScopeFilterReport, error) {
	var report ScopeFilterReport
	if scope == ScopeUnknown || result.Graphs == nil {
		return result, report, nil
	}
	seen := make(map[string]struct{})
	entries := make([]GraphEntry, 0, len(result.Graphs.Entries))
	for _, entry := range result.Graphs.Entries {
		if entry.Graph == nil {
			entries = append(entries, entry)
			continue
		}
		graphView, entryReport, err := FilterGraphByScopeWithReport(entry.Graph, scope)
		if err != nil {
			return DetectionResult{}, ScopeFilterReport{}, err
		}
		// Deduplicated across entries: consolidation has not run yet, so one
		// dependency reached from two manifests appears in both, and a count
		// that double-reports it overstates what the filter could not narrow.
		for _, id := range entryReport.Unasserted {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			report.Unasserted = append(report.Unasserted, id)
		}
		entry.Graph = graphView
		entry.Packages = filterEntryPackagesByGraph(entry.Packages, graphView)
		entries = append(entries, entry)
	}
	sort.Strings(report.Unasserted)
	result.Graphs = &GraphContainer{Entries: entries}
	return result, report, nil
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
