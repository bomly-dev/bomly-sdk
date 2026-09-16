package plugin

import (
	"sort"

	"github.com/bomly-dev/bomly-sdk/model"
)

// FilterDetectionResultByScope applies scope filtering to each graph entry in a
// detector result, discarding the report.
func FilterDetectionResultByScope(result DetectionResult, scope model.Scope) (DetectionResult, error) {
	filtered, _, err := FilterDetectionResultByScopeWithReport(result, scope)
	return filtered, err
}

// FilterDetectionResultByScopeWithReport is FilterDetectionResultByScope, and
// also says which dependencies a runtime view kept across every entry because
// they asserted no scope. This is the variant a pipeline calls: it is the one
// hop that sees the whole result, so it is where a user-facing warning about
// how much the filter could not narrow can be raised once rather than per
// entry.
func FilterDetectionResultByScopeWithReport(result DetectionResult, scope model.Scope) (DetectionResult, model.ScopeFilterReport, error) {
	var report model.ScopeFilterReport
	if scope == model.ScopeUnknown || result.Graphs == nil {
		return result, report, nil
	}
	seen := make(map[string]struct{})
	entries := make([]model.GraphEntry, 0, len(result.Graphs.Entries))
	for _, entry := range result.Graphs.Entries {
		if entry.Graph == nil {
			entries = append(entries, entry)
			continue
		}
		graphView, entryReport, err := model.FilterGraphByScopeWithReport(entry.Graph, scope)
		if err != nil {
			return DetectionResult{}, model.ScopeFilterReport{}, err
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
	result.Graphs = &model.GraphContainer{Entries: entries}
	return result, report, nil
}

func filterEntryPackagesByGraph(packages []*model.Package, graph *model.Graph) []*model.Package {
	if len(packages) == 0 || graph == nil {
		return packages
	}
	allowed := make(map[string]struct{}, graph.Size())
	graph.WalkDependencyNodes(func(dep *model.DependencyNode) bool {
		allowed[dep.NodeID()] = struct{}{}
		return true
	})
	if len(allowed) == 0 {
		return nil
	}
	filtered := make([]*model.Package, 0, len(packages))
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
