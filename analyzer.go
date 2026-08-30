package sdk

import (
	"context"
	"encoding/json"
	"io"
)

// AnalyzerFilter narrows analyzer selection for a request.
type AnalyzerFilter struct {
	Include []string
	Exclude []string
}

// Includes reports whether an analyzer name is explicitly allowed.
func (f AnalyzerFilter) Includes(name string) bool {
	return includesName(f.Include, name)
}

// Excludes reports whether an analyzer name is explicitly denied.
func (f AnalyzerFilter) Excludes(name string) bool {
	return excludesName(f.Exclude, name)
}

// AnalyzerDescriptor describes an analyzer registration.
type AnalyzerDescriptor struct {
	Name                string           `json:"name"`
	DisplayName         string           `json:"displayName,omitempty"`
	Aliases             []string         `json:"aliases,omitempty"`
	Tags                []string         `json:"tags,omitempty"`
	SupportedEcosystems []Ecosystem      `json:"supportedEcosystems,omitempty"`
	SupportedManagers   []PackageManager `json:"supportedManagers,omitempty"`
	// SupportedLanguages is the analyzer's primary dispatch axis.
	SupportedLanguages []Language `json:"supportedLanguages,omitempty"`
	// SupportedTiers communicates the precision the analyzer can deliver.
	SupportedTiers []ReachabilityTier `json:"supportedTiers,omitempty"`
	// Capabilities advertises optional protocol features this analyzer
	// supports, such as CapabilityPackageUpdates.
	Capabilities []string `json:"capabilities,omitempty"`
	// ConfigSchema optionally documents the analyzer's configuration block as
	// a JSON Schema. Build it with ConfigSchemaFor.
	ConfigSchema json.RawMessage `json:"configSchema,omitempty"`
}

// AnalyzeRequest defines input for an analyzer. Analyzers annotate
// Vulnerability.Reachability on packages in the Registry.
type AnalyzeRequest struct {
	ProjectPath     string           `json:"projectPath,omitempty"`
	ExecutionTarget ExecutionTarget  `json:"executionTarget"`
	SubprojectInfo  Subproject       `json:"subprojectInfo"`
	Ecosystem       Ecosystem        `json:"ecosystem,omitempty"`
	PackageManager  PackageManager   `json:"packageManager,omitempty"`
	Language        Language         `json:"language,omitempty"`
	Query           PackageQuery     `json:"query"`
	Graph           *Graph           `json:"graph,omitempty"`
	Registry        *PackageRegistry `json:"registry,omitempty"`
	Target          *DependencyNode  `json:"target,omitempty"`
	AnalyzerFilter  AnalyzerFilter   `json:"analyzerFilter"`
	// AcceptPackageUpdates signals that the host understands
	// AnalyzeResult.PackageUpdates. Analyzers advertising
	// CapabilityPackageUpdates may return updates instead of a full registry
	// only when this is true.
	AcceptPackageUpdates bool      `json:"acceptPackageUpdates,omitempty"`
	Stderr               io.Writer `json:"-"`
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
	Registry       *PackageRegistry             `json:"registry,omitempty"`
	PackageUpdates []*Package                   `json:"packageUpdates,omitempty"`
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
