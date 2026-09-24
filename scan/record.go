// Package scan defines the scan record: the document one run of `bomly scan`
// produces, in the shape its JSON output has always had -- three
// collections, manifests, packages and findings, joined by package URL --
// plus what that output never said about itself: what was scanned, when, by
// which components, and what the verdict was.
//
// A record relates to an SBOM in both directions. Its manifests section is
// what package sbom projects into a document and reads back out of one, so
// an SBOM can be produced from a record with the codec that already exists,
// and a scan that ingested an SBOM yields a record whose manifest carries
// that document's own assertions. Its packages and findings sections hold
// what no SBOM can say: enrichment, policy outcomes, waivers, a verdict.
//
// The schema is versioned by SchemaVersion and grows only additively within
// a version: readers ignore keys they do not know, and Decode refuses a
// record of another version rather than guessing at it. Encode is
// byte-stable -- every collection is written in a fixed order -- so a digest
// over a record's bytes identifies its content, and each section carries its
// own digest so a reader can tell which of the three changed.
package scan

import (
	"time"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

// SchemaVersion names the record schema this package writes and reads.
const SchemaVersion = "bomly.scan.v1"

// Record is one scan: what was scanned, what was found, and what was decided.
type Record struct {
	// SchemaVersion is SchemaVersion; the one key every record carries.
	SchemaVersion string `json:"schema_version"`
	// Command is the command that produced the record ("scan").
	Command string `json:"command,omitempty"`
	// Subject is what was scanned, in terms that identify it outside the
	// machine it was scanned on.
	Subject Subject `json:"subject,omitzero"`
	// Run is the execution that produced the record.
	Run Run `json:"run,omitzero"`
	// Manifests are the detection-stage results, one per manifest the scan
	// resolved, each with its lean dependency list.
	Manifests []Manifest `json:"manifests,omitempty"`
	// Packages is the matching-stage registry: one package per package URL,
	// carrying the enrichment. Sorted by package URL.
	Packages []*model.Package `json:"packages,omitempty"`
	// Findings are the audit-stage results, referencing packages by URL.
	Findings []model.Finding `json:"findings,omitempty"`
	// AuditSummary counts the findings by severity.
	AuditSummary *AuditSummary `json:"audit_summary,omitempty"`
	// Warnings are the typed detector warnings the run surfaced.
	Warnings []plugin.DetectorWarning `json:"warnings,omitempty"`
	// Verdict is the policy outcome of the whole run.
	Verdict Verdict `json:"verdict,omitempty"`
	// Policy names the policy the findings were evaluated against.
	Policy *PolicyRef `json:"policy,omitempty"`
	// Waivers are the accepted findings that shaped the verdict.
	Waivers []Waiver `json:"waivers,omitempty"`
	// Metadata carries run statistics.
	Metadata Metadata `json:"metadata,omitzero"`
	// Digests are content digests over each section's encoded bytes, filled
	// by Encode and verified by Decode when present.
	Digests *SectionDigests `json:"digests,omitempty"`
}

// Subject identifies what was scanned. It deliberately has no field for a
// local path: a record is read away from the machine that produced it, and a
// path there identifies nothing here.
type Subject struct {
	Kind          plugin.ExecutionTargetKind `json:"kind,omitempty"`
	RepositoryURL string                     `json:"repository_url,omitempty"`
	// Ref is the revision that was asked for; CommitSHA is the one found.
	Ref       string `json:"ref,omitempty"`
	CommitSHA string `json:"commit_sha,omitempty"`
	// ImageDigest identifies a container image subject.
	ImageDigest string `json:"image_digest,omitempty"`
}

// Run describes one execution of the pipeline.
type Run struct {
	ID          string      `json:"id,omitempty"`
	Correlator  string      `json:"correlator,omitempty"`
	StartedAt   time.Time   `json:"started_at,omitzero"`
	CompletedAt time.Time   `json:"completed_at,omitzero"`
	Tool        Tool        `json:"tool,omitzero"`
	Components  []Component `json:"components,omitempty"`
	Options     Options     `json:"options,omitzero"`
}

// Tool is the host that ran the scan.
type Tool struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// Component is one detector, matcher, auditor or analyzer that took part.
type Component struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Role    string `json:"role,omitempty"`
	Origin  string `json:"origin,omitempty"`
}

// Options are the run's stage selections and policy inputs.
type Options struct {
	Enrich  bool     `json:"enrich,omitempty"`
	Analyze bool     `json:"analyze,omitempty"`
	Audit   bool     `json:"audit,omitempty"`
	FailOn  []string `json:"fail_on,omitempty"`
}

// Manifest is one resolved manifest and the dependencies it declares.
type Manifest struct {
	Path           string                    `json:"path,omitempty"`
	Kind           model.ManifestKind        `json:"kind,omitempty"`
	Subproject     string                    `json:"subproject,omitempty"`
	Ecosystem      model.Ecosystem           `json:"ecosystem,omitempty"`
	PackageManager model.PackageManager      `json:"package_manager,omitempty"`
	Detector       string                    `json:"detector,omitempty"`
	Resolution     *model.ResolutionMetadata `json:"resolution,omitempty"`
	Dependencies   []Dependency              `json:"dependencies,omitempty"`
}

// Dependency is the lean projection of a graph node: identity, scope, edges,
// and the detection-time facts a manifest states. Enrichment lives once, on
// the package PackageRef names.
type Dependency struct {
	ID         string                  `json:"id,omitempty"`
	Name       string                  `json:"name,omitempty"`
	Version    string                  `json:"version,omitempty"`
	PURL       string                  `json:"purl,omitempty"`
	Scopes     []model.Scope           `json:"scopes,omitempty"`
	DependsOn  []string                `json:"depends_on,omitempty"`
	Matched    bool                    `json:"matched,omitempty"`
	PackageRef string                  `json:"package_ref,omitempty"`
	Locations  []model.PackageLocation `json:"locations,omitempty"`
	Licenses   []model.PackageLicense  `json:"licenses,omitempty"`
}

// AuditSummary counts findings by severity.
type AuditSummary struct {
	Critical int `json:"critical,omitempty"`
	High     int `json:"high,omitempty"`
	Medium   int `json:"medium,omitempty"`
	Low      int `json:"low,omitempty"`
	Unknown  int `json:"unknown,omitempty"`
	Total    int `json:"total,omitempty"`
}

// Verdict is the policy outcome of a run.
type Verdict string

const (
	// VerdictPass means no finding failed policy.
	VerdictPass Verdict = "pass"
	// VerdictWarn means findings exist but none failed policy.
	VerdictWarn Verdict = "warn"
	// VerdictFail means at least one finding failed policy.
	VerdictFail Verdict = "fail"
)

// PolicyRef names the policy a run evaluated against.
type PolicyRef struct {
	Name        string    `json:"name,omitempty"`
	Digest      string    `json:"digest,omitempty"`
	EvaluatedAt time.Time `json:"evaluated_at,omitzero"`
}

// Waiver is an accepted finding: which one, on whose say, until when.
type Waiver struct {
	ID              string    `json:"id,omitempty"`
	PackageRef      string    `json:"package_ref,omitempty"`
	VulnerabilityID string    `json:"vulnerability_id,omitempty"`
	RuleID          string    `json:"rule_id,omitempty"`
	Justification   string    `json:"justification,omitempty"`
	ApprovedBy      string    `json:"approved_by,omitempty"`
	CreatedAt       time.Time `json:"created_at,omitzero"`
	ExpiresAt       time.Time `json:"expires_at,omitzero"`
}

// Metadata carries run statistics.
type Metadata struct {
	DurationMS          int64                               `json:"duration_ms,omitempty"`
	ReachabilityEnabled bool                                `json:"reachability_enabled,omitempty"`
	ScorecardEnabled    bool                                `json:"scorecard_enabled,omitempty"`
	AnalyzerRuns        []string                            `json:"analyzer_runs,omitempty"`
	AnalyzerStats       map[string]plugin.ReachabilityStats `json:"analyzer_stats,omitempty"`
}

// SectionDigests are "sha256:<hex>" digests over each section's encoded
// bytes, so a reader can tell which of the three collections changed
// between two records without comparing them.
type SectionDigests struct {
	Manifests string `json:"manifests,omitempty"`
	Packages  string `json:"packages,omitempty"`
	Findings  string `json:"findings,omitempty"`
}
