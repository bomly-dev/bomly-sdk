package scan

import (
	"github.com/bomly-dev/bomly-sdk/graphview"
	"github.com/bomly-dev/bomly-sdk/model"
)

// FromGraphEntries builds a record's three collections from what a pipeline
// holds: the graph entries detection produced, the registry matching filled,
// and the findings auditing raised. One Manifest is written per entry; its
// Subproject, Ecosystem, PackageManager and Detector are not derivable from
// an entry and are the caller's to fill, as are Subject, Run, Verdict and
// Policy. The result is not yet canonical; Encode orders it.
//
// A dependency's edges name only nodes the record defines, stepping through
// manifest nodes the way a document does (graphview.ChildrenAmong): a
// workspace is module -> child manifest -> child module, and the manifest
// in the middle is structural.
func FromGraphEntries(entries []model.GraphEntry, registry *model.PackageRegistry, findings []model.Finding) *Record {
	r := &Record{SchemaVersion: SchemaVersion, Command: "scan"}
	for _, entry := range entries {
		manifest := Manifest{Path: entry.Manifest.Path, Kind: entry.Manifest.Kind, Resolution: entry.Manifest.Resolution}
		if entry.Graph != nil {
			manifest.Dependencies = dependenciesOf(entry.Graph)
		}
		r.Manifests = append(r.Manifests, manifest)
	}
	if registry != nil {
		r.Packages = registry.All()
	}
	if len(findings) > 0 {
		r.Findings = append([]model.Finding(nil), findings...)
		r.AuditSummary = summarize(findings)
	}
	return r
}

// dependenciesOf projects every module and dependency node of a graph. A
// manifest node is structural and is never listed; its children are reached
// through it.
func dependenciesOf(g *model.Graph) []Dependency {
	present := make(map[string]struct{})
	for _, node := range g.Nodes() {
		if node.Kind() != model.NodeKindManifest {
			present[node.NodeID()] = struct{}{}
		}
	}
	out := make([]Dependency, 0, len(present))
	for _, node := range g.Nodes() {
		if node.Kind() == model.NodeKindManifest {
			continue
		}
		dep := Dependency{
			ID:        node.NodeID(),
			Name:      model.NodeDisplayName(node),
			Version:   model.NodeVersion(node),
			PURL:      model.NodePURL(node),
			Locations: node.NodeLocations(),
			DependsOn: graphview.ChildrenAmong(g, node.NodeID(), present),
		}
		if d, ok := model.AsDependencyNode(node); ok && d != nil {
			dep.Scopes = d.AttributedScopes()
			dep.Matched = d.Matched
			dep.PackageRef = d.PackageRef
			dep.Licenses = model.DetectionLicenses(d)
		}
		out = append(out, dep)
	}
	return out
}

// summarize counts findings by severity band.
func summarize(findings []model.Finding) *AuditSummary {
	s := &AuditSummary{Total: len(findings)}
	for _, f := range findings {
		switch model.ParseSeverityLevel(string(f.Severity)) {
		case model.ParseSeverityLevel("critical"):
			s.Critical++
		case model.ParseSeverityLevel("high"):
			s.High++
		case model.ParseSeverityLevel("medium"):
			s.Medium++
		case model.ParseSeverityLevel("low"):
			s.Low++
		default:
			s.Unknown++
		}
	}
	return s
}

// VerdictOf derives the run's verdict from its findings: fail when any
// finding's policy status is fail or unset (an unset status keeps the
// historical fail behaviour), warn when findings exist but none fail, pass
// otherwise.
func VerdictOf(findings []model.Finding) Verdict {
	if len(findings) == 0 {
		return VerdictPass
	}
	for _, f := range findings {
		if f.PolicyStatus == "" || f.PolicyStatus == model.FindingPolicyStatusFail {
			return VerdictFail
		}
	}
	return VerdictWarn
}
