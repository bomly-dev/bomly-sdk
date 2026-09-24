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

// VulnerabilityRef names one advisory on one package.
type VulnerabilityRef struct {
	PackageRef      string `json:"package_ref,omitempty"`
	VulnerabilityID string `json:"vulnerability_id,omitempty"`
}

// FindingRef names one finding on one package.
type FindingRef struct {
	ID         string `json:"id,omitempty"`
	PackageRef string `json:"package_ref,omitempty"`
}

// Compare reports what changed from base to head. Dependencies are compared
// by rebuilding each record's dependency graph -- across all its manifests,
// folded by identity -- and handing the pair to model.Compare, so the answer
// is the graph comparison's, not a second one. Advisories and findings are
// compared by identity: an advisory is (package, ID), a finding is (ID,
// package).
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

// graphOf rebuilds a record's dependency nodes and the edges among them.
// Module nodes are omitted: model.Compare reads dependency nodes only, and
// a module's identity is its manifest path, which the comparison ignores.
func graphOf(r *Record) (*model.Graph, error) {
	g := model.New()
	type edge struct{ from, to string }
	var edges []edge
	for _, manifest := range r.Manifests {
		for _, dep := range manifest.Dependencies {
			if !strings.HasPrefix(dep.ID, "pkg:") {
				continue
			}
			node, err := model.NewDependencyNodeFromPURL(dep.ID)
			if err != nil {
				return nil, fmt.Errorf("manifest %q dependency %q: %w", manifest.Path, dep.ID, err)
			}
			node.Scopes = append([]model.Scope(nil), dep.Scopes...)
			node.Locations = append([]model.PackageLocation(nil), dep.Locations...)
			if _, err := g.InsertNode(node); err != nil {
				return nil, err
			}
			for _, target := range dep.DependsOn {
				edges = append(edges, edge{dep.ID, target})
			}
		}
	}
	for _, e := range edges {
		if _, ok := g.Node(e.to); !ok || e.from == e.to {
			continue
		}
		if err := g.AddEdge(e.from, e.to); err != nil {
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
				out[VulnerabilityRef{PackageRef: pkg.PURL, VulnerabilityID: v.ID}] = struct{}{}
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
			return refs[i].VulnerabilityID < refs[j].VulnerabilityID
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
			out[FindingRef{ID: f.ID, PackageRef: f.PackageRef}] = struct{}{}
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
		return func(i, j int) bool {
			if refs[i].ID != refs[j].ID {
				return refs[i].ID < refs[j].ID
			}
			return refs[i].PackageRef < refs[j].PackageRef
		}
	}
	sort.Slice(added, less(added))
	sort.Slice(removed, less(removed))
	return added, removed
}
