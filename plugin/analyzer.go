package plugin

import (
	"context"
	"encoding/json"
	"io"
	"slices"

	"github.com/bomly-dev/bomly-sdk/model"
)

// AnalyzerFilter narrows analyzer selection for a request.
//
// The json tags keep their capitals. These fields carried no tag, so v1
// peers send "Include" and "Exclude"; lowercasing one renames the wire
// field. TestWireV1FilterNamesKeepTheirCapitals fails if it happens.
type AnalyzerFilter struct {
	Include []string `json:"Include,omitempty"`
	Exclude []string `json:"Exclude,omitempty"`
}

// Includes reports whether an analyzer name is explicitly allowed.
func (f AnalyzerFilter) Includes(name string) bool {
	return includesComponentName(f.Include, name)
}

// Excludes reports whether an analyzer name is explicitly denied.
func (f AnalyzerFilter) Excludes(name string) bool {
	return excludesComponentName(f.Exclude, name)
}

// AnalyzerDescriptor describes an analyzer registration.
type AnalyzerDescriptor struct {
	Name                string                 `json:"name"`
	DisplayName         string                 `json:"displayName,omitempty"`
	Aliases             []string               `json:"aliases,omitempty"`
	Tags                []string               `json:"tags,omitempty"`
	SupportedEcosystems []model.Ecosystem      `json:"supportedEcosystems,omitempty"`
	SupportedManagers   []model.PackageManager `json:"supportedManagers,omitempty"`
	// Version is the component's own release version; see
	// ComponentDescriptor.Version. Optional.
	Version string `json:"version,omitempty"`
	// Requires declares the pipeline inputs and host capabilities the
	// component needs; see Requirement. Optional: absent means legacy and
	// unspecified, never "needs nothing". Ready and Applicable still run.
	// Gate: Requirements.Validate, through the kind's Validate*Descriptor.
	Requires Requirements `json:"requires,omitempty"`
	// SupportedLanguages is the analyzer's primary dispatch axis.
	SupportedLanguages []model.Language `json:"supportedLanguages,omitempty"`
	// SupportedTiers communicates the precision the analyzer can deliver.
	SupportedTiers []model.ReachabilityTier `json:"supportedTiers,omitempty"`
	// Capabilities advertises optional protocol features this analyzer
	// supports, such as CapabilityPackageUpdates.
	Capabilities []string `json:"capabilities,omitempty"`
	// ConfigSchema optionally documents the analyzer's configuration block as
	// a JSON Schema. Build it with ConfigSchemaFor.
	ConfigSchema json.RawMessage `json:"configSchema,omitempty"`
}

// Clone returns a deep copy of the descriptor: every slice, the declared
// requirements and the config schema are copied, so a host that keeps a
// descriptor cannot have it changed by the component that returned it.
func (d AnalyzerDescriptor) Clone() AnalyzerDescriptor {
	clone := d
	clone.Aliases = slices.Clone(d.Aliases)
	clone.Tags = slices.Clone(d.Tags)
	clone.SupportedEcosystems = slices.Clone(d.SupportedEcosystems)
	clone.SupportedManagers = slices.Clone(d.SupportedManagers)
	clone.SupportedLanguages = slices.Clone(d.SupportedLanguages)
	clone.SupportedTiers = slices.Clone(d.SupportedTiers)
	clone.Capabilities = slices.Clone(d.Capabilities)
	clone.Requires = slices.Clone(d.Requires)
	clone.ConfigSchema = slices.Clone(d.ConfigSchema)
	return clone
}

// AnalyzeRequest defines input for an analyzer. Analyzers annotate
// Vulnerability.Reachability on packages in the Registry.
type AnalyzeRequest struct {
	ProjectPath     string                 `json:"projectPath,omitempty"`
	ExecutionTarget ExecutionTarget        `json:"executionTarget"`
	SubprojectInfo  Subproject             `json:"subprojectInfo"`
	Ecosystem       model.Ecosystem        `json:"ecosystem,omitempty"`
	PackageManager  model.PackageManager   `json:"packageManager,omitempty"`
	Language        model.Language         `json:"language,omitempty"`
	Query           PackageQuery           `json:"query"`
	Graph           *model.Graph           `json:"graph,omitempty"`
	Registry        *model.PackageRegistry `json:"registry,omitempty"`
	Target          *model.DependencyNode  `json:"target,omitempty"`
	AnalyzerFilter  AnalyzerFilter         `json:"analyzerFilter"`
	// AcceptPackageUpdates signals that the host understands
	// AnalyzeResult.PackageUpdates. Analyzers advertising
	// CapabilityPackageUpdates may return updates instead of a full registry
	// only when this is true.
	AcceptPackageUpdates bool      `json:"acceptPackageUpdates,omitempty"`
	Stderr               io.Writer `json:"-"`
}

// Clone returns a deep copy of the request that shares no mutable memory
// with it, on the terms MatchRequest.Clone states: the graph, registry and
// target are copied, every slice is copied, and Stderr is kept as the host's
// writer.
func (r AnalyzeRequest) Clone() AnalyzeRequest {
	clone := r
	clone.SubprojectInfo = r.SubprojectInfo.Clone()
	clone.Graph = r.Graph.Clone()
	clone.Registry = r.Registry.Clone()
	clone.Target = r.Target.Clone()
	clone.AnalyzerFilter = AnalyzerFilter{
		Include: slices.Clone(r.AnalyzerFilter.Include),
		Exclude: slices.Clone(r.AnalyzerFilter.Exclude),
	}
	return clone
}

// ReachabilityStats tallies the per-analyzer outcome distribution.
type ReachabilityStats struct {
	Reachable     int `json:"reachable,omitempty"`
	Unreachable   int `json:"unreachable,omitempty"`
	Unknown       int `json:"unknown,omitempty"`
	NotApplicable int `json:"not_applicable,omitempty"`
}

// AnalyzeResult contains the registry after analyzer enrichment.
// An analyzer returns either Registry (the full annotated registry — the
// protocol v1 baseline) or, when the request set AcceptPackageUpdates,
// PackageUpdates: only the packages it touched. The host merges updates into
// its registry by PURL. When Registry is non-nil it wins and PackageUpdates
// is ignored.
type AnalyzeResult struct {
	Registry       *model.PackageRegistry       `json:"registry,omitempty"`
	PackageUpdates []*model.Package             `json:"packageUpdates,omitempty"`
	AnalyzerRuns   []string                     `json:"analyzerRuns,omitempty"`
	AnalyzerStats  map[string]ReachabilityStats `json:"analyzerStats,omitempty"`
}

// Analyzer enriches Vulnerability entries with reachability data derived from
// code analysis. Analyzers run after matchers, before auditors, and must never
// abort the pipeline on failure.
type Analyzer interface {
	Descriptor() AnalyzerDescriptor
	// Ready reports whether the analyzer can run for the given request. It
	// returns nil when ready and a non-nil error describing the reason
	// otherwise. Implementations may perform lightweight, cancellable I/O and
	// should honor ctx.
	Ready(context.Context, AnalyzeRequest) error
	Applicable(context.Context, AnalyzeRequest) (bool, error)
	Analyze(context.Context, AnalyzeRequest) (AnalyzeResult, error)
}

// AnalyzeResponse is the analyzer response payload exposed to plugins.
type AnalyzeResponse = AnalyzeResult
