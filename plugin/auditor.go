package plugin

import (
	"context"
	"encoding/json"
	"io"
	"slices"

	"github.com/bomly-dev/bomly-sdk/model"
)

// AuditorFilter narrows auditor selection for a request.
//
// The json tags keep their capitals. These fields carried no tag, so v1
// peers send "Include" and "Exclude"; lowercasing one renames the wire
// field. TestWireV1FilterNamesKeepTheirCapitals fails if it happens.
type AuditorFilter struct {
	Include []string `json:"Include,omitempty"`
	Exclude []string `json:"Exclude,omitempty"`
}

// Includes reports whether an auditor name is explicitly allowed.
func (f AuditorFilter) Includes(name string) bool {
	return includesComponentName(f.Include, name)
}

// Excludes reports whether an auditor name is explicitly denied.
func (f AuditorFilter) Excludes(name string) bool {
	return excludesComponentName(f.Exclude, name)
}

// AuditRequest defines input for an auditor. Auditors read the dependency Graph
// and the package Registry and emit reference-style findings.
type AuditRequest struct {
	ProjectPath     string                 `json:"projectPath,omitempty"`
	ExecutionTarget ExecutionTarget        `json:"executionTarget"`
	SubprojectInfo  Subproject             `json:"subprojectInfo"`
	Ecosystem       model.Ecosystem        `json:"ecosystem,omitempty"`
	PackageManager  model.PackageManager   `json:"packageManager,omitempty"`
	Query           PackageQuery           `json:"query"`
	Graph           *model.Graph           `json:"graph,omitempty"`
	BaselineGraph   *model.Graph           `json:"baselineGraph,omitempty"`
	Registry        *model.PackageRegistry `json:"registry,omitempty"`
	Target          *model.DependencyNode  `json:"target,omitempty"`
	// DependencyDetailChanges contains canonical head-side transitions for a
	// diff audit. Scan and explain requests leave it empty.
	DependencyDetailChanges []model.DependencyDetailTransition `json:"dependencyDetailChanges,omitempty"`
	AuditorFilter           AuditorFilter                      `json:"auditorFilter"`
	Stderr                  io.Writer                          `json:"-"`
}

// AuditResult contains findings and scores from one auditor.
type AuditResult struct {
	Findings        []model.Finding   `json:"findings,omitempty"`
	RiskScores      []model.RiskScore `json:"riskScores,omitempty"`
	AuditorRuns     []string          `json:"auditorRuns,omitempty"`
	AuditorFindings map[string]int    `json:"auditorFindings,omitempty"`
}

// AuditorDescriptor describes an auditor registration.
type AuditorDescriptor struct {
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
	// ConfigSchema optionally documents the auditor's configuration block as
	// a JSON Schema. Build it with ConfigSchemaFor.
	ConfigSchema json.RawMessage `json:"configSchema,omitempty"`
}

// Clone returns a deep copy of the descriptor: every slice, the declared
// requirements and the config schema are copied, so a host that keeps a
// descriptor cannot have it changed by the component that returned it.
func (d AuditorDescriptor) Clone() AuditorDescriptor {
	clone := d
	clone.Aliases = slices.Clone(d.Aliases)
	clone.Tags = slices.Clone(d.Tags)
	clone.SupportedEcosystems = slices.Clone(d.SupportedEcosystems)
	clone.SupportedManagers = slices.Clone(d.SupportedManagers)
	clone.Requires = slices.Clone(d.Requires)
	clone.ConfigSchema = slices.Clone(d.ConfigSchema)
	return clone
}

// Auditor analyzes graphs or components and returns findings.
type Auditor interface {
	Descriptor() AuditorDescriptor
	// Ready reports whether the auditor can run for the given request. It
	// returns nil when ready and a non-nil error describing the reason
	// otherwise. Implementations may perform lightweight, cancellable I/O and
	// should honor ctx.
	Ready(context.Context, AuditRequest) error
	Applicable(context.Context, AuditRequest) (bool, error)
	Audit(context.Context, AuditRequest) (AuditResult, error)
}

// AuditResponse is the auditor response payload exposed to plugins.
//
// It aliases AuditResult so plugin code can name payload types by role while
// sharing the same transport shape Bomly core uses internally.
type AuditResponse = AuditResult
