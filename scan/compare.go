package scan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-sdk/model"
)

// Diff is what changed between two records: the dependency changes the
// graph comparison reports, and the advisories and findings that appeared
// or disappeared, by identity.
type Diff struct {
	Dependencies           model.Diff
	AddedVulnerabilities   []VulnerabilityRef
	RemovedVulnerabilities []VulnerabilityRef
	AddedFindings          []FindingRef
	RemovedFindings        []FindingRef
}

// VulnerabilityRef names one advisory on one package. The identity is the
// one Package.mergeVulnerabilities unions by -- source and ID -- so an
// advisory that moved from one source to another under the same ID is a
// removal and an addition, not nothing.
type VulnerabilityRef struct {
	PackageRef      string `json:"package_ref,omitempty"`
	VulnerabilityID string `json:"vulnerability_id,omitempty"`
	Source          string `json:"source,omitempty"`
}

// FindingRef names one finding: the identity Encode orders findings by,
// less the provenance (auditor, source), which does not make a second
// finding of a second finding. A vulnerability finding and a policy
// finding under one ID on one package are two findings.
type FindingRef struct {
	ID              string            `json:"id,omitempty"`
	PackageRef      string            `json:"package_ref,omitempty"`
	Kind            model.FindingKind `json:"kind,omitempty"`
	VulnerabilityID string            `json:"vulnerability_id,omitempty"`
	RuleID          string            `json:"rule_id,omitempty"`
}

func findingRefOf(f model.Finding) FindingRef {
	return FindingRef{ID: f.ID, PackageRef: f.PackageRef, Kind: f.Kind, VulnerabilityID: f.VulnerabilityID, RuleID: f.RuleID}
}

func (r FindingRef) key() string {
	return strings.Join([]string{r.ID, r.PackageRef, string(r.Kind), r.VulnerabilityID, r.RuleID}, "\x00")
}

// Compare reports what changed from base to head. Dependencies are compared
// by rebuilding each record's dependency graph -- across all its manifests,
// folded by identity -- and handing the pair to model.Compare, so the answer
// is the graph comparison's, not a second one. Advisories and findings are
// compared by identity: an advisory is (package, source, ID), a finding is
// (ID, package, kind, vulnerability, rule).
func Compare(base, head *Record) (Diff, error) {
	if base == nil || head == nil {
		return Diff{}, fmt.Errorf("scan compare: both records are required")
	}
	baseGraph, err := graphOf(base)
	if err != nil {
		return Diff{}, fmt.Errorf("scan compare: base: %w", err)
	}
	headGraph, err := graphOf(head)
	if err != nil {
		return Diff{}, fmt.Errorf("scan compare: head: %w", err)
	}
	diff := Diff{Dependencies: model.Compare(baseGraph, headGraph)}
	diff.AddedVulnerabilities, diff.RemovedVulnerabilities = vulnerabilityDelta(base.Packages, head.Packages)
	diff.AddedFindings, diff.RemovedFindings = findingDelta(base.Findings, head.Findings)
	return diff, nil
}

// graphOf rebuilds a record's module and dependency nodes and the edges
// among them. Module nodes matter even though the comparison reports only
// dependencies: a dependency is direct when it hangs off a module, and
// without the module edges every root of the rebuilt graph would read as
// direct and a transitive-to-direct change would go unreported. Manifest
// nodes are not in a record -- the record steps through them when it writes
// a module's edges -- so a module stands at the root here, as the
// comparison expects. A module the record cannot mint (no name and no
// package URL) is left out, and a manifest with no module at all has no
// structural root here; in both cases each dependency's stated
// relationship stands in, which the comparison honors over one derived
// from the edges.
func graphOf(r *Record) (*model.Graph, error) {
	g := model.New()
	type edge struct{ from, to string }
	var edges []edge
	// A node's identity is minted from its package URL, so the ID a record
	// wrote and the ID the graph holds can differ in spelling; edges are
	// resolved through this map rather than by the record's IDs.
	canonical := make(map[string]string)
	for _, manifest := range r.Manifests {
		for _, dep := range manifest.Dependencies {
			var node model.GraphNode
			if strings.HasPrefix(dep.ID, "pkg:") {
				dependency, err := model.NewDependencyNodeFromPURL(dep.ID)
				if err != nil {
					return nil, fmt.Errorf("manifest %q dependency %q: %w", manifest.Path, dep.ID, err)
				}
				dependency.Source = dep.Source
				dependency.Relationship = dep.Relationship
				dependency.Scopes = append([]model.Scope(nil), dep.Scopes...)
				dependency.Locations = append([]model.PackageLocation(nil), dep.Locations...)
				node = dependency
			} else {
				module, err := model.NewModuleNode(manifest.Path, model.Coordinates{
					PURL: dep.PURL, Name: dep.Name, Version: dep.Version,
					Ecosystem: manifest.Ecosystem, PackageManager: manifest.PackageManager,
				})
				if err != nil {
					continue
				}
				node = module
			}
			if _, err := g.InsertNode(node); err != nil {
				return nil, err
			}
			canonical[dep.ID] = node.NodeID()
			for _, target := range dep.DependsOn {
				edges = append(edges, edge{node.NodeID(), target})
			}
		}
	}
	for _, e := range edges {
		to, ok := canonical[e.to]
		if !ok || e.from == to {
			continue
		}
		if err := g.AddEdge(e.from, to); err != nil {
			return nil, err
		}
	}
	return g, nil
}

func vulnerabilityDelta(base, head []*model.Package) (added, removed []VulnerabilityRef) {
	index := func(packages []*model.Package) map[VulnerabilityRef]struct{} {
		out := make(map[VulnerabilityRef]struct{})
		for _, pkg := range packages {
			if pkg == nil {
				continue
			}
			for _, v := range pkg.Vulnerabilities {
				out[VulnerabilityRef{PackageRef: pkg.PURL, VulnerabilityID: v.ID, Source: v.Source}] = struct{}{}
			}
		}
		return out
	}
	left, right := index(base), index(head)
	for ref := range right {
		if _, ok := left[ref]; !ok {
			added = append(added, ref)
		}
	}
	for ref := range left {
		if _, ok := right[ref]; !ok {
			removed = append(removed, ref)
		}
	}
	less := func(refs []VulnerabilityRef) func(int, int) bool {
		return func(i, j int) bool {
			if refs[i].PackageRef != refs[j].PackageRef {
				return refs[i].PackageRef < refs[j].PackageRef
			}
			if refs[i].VulnerabilityID != refs[j].VulnerabilityID {
				return refs[i].VulnerabilityID < refs[j].VulnerabilityID
			}
			return refs[i].Source < refs[j].Source
		}
	}
	sort.Slice(added, less(added))
	sort.Slice(removed, less(removed))
	return added, removed
}

func findingDelta(base, head []model.Finding) (added, removed []FindingRef) {
	index := func(findings []model.Finding) map[FindingRef]struct{} {
		out := make(map[FindingRef]struct{}, len(findings))
		for _, f := range findings {
			out[findingRefOf(f)] = struct{}{}
		}
		return out
	}
	left, right := index(base), index(head)
	for ref := range right {
		if _, ok := left[ref]; !ok {
			added = append(added, ref)
		}
	}
	for ref := range left {
		if _, ok := right[ref]; !ok {
			removed = append(removed, ref)
		}
	}
	less := func(refs []FindingRef) func(int, int) bool {
		return func(i, j int) bool { return refs[i].key() < refs[j].key() }
	}
	sort.Slice(added, less(added))
	sort.Slice(removed, less(removed))
	return added, removed
}
