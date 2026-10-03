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
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

// IteratedCollections are the record's collections that are always
// written, as [] when empty, because they are the ones a consumer iterates:
// a script that walks `.findings[]` or `.manifests[].dependencies[].depends_on[]`
// must not break on a run that found nothing. An empty array and an absent
// key mean the same thing in this record -- none recorded -- so writing the
// array adds no claim; it only makes the shape stable. Other optional
// fields, collections included, are omitted when empty. Adding a key to
// this list is additive within bomly.scan.v1: a reader that tolerated its
// absence also reads an empty array.
var IteratedCollections = []string{
	"manifests", "packages", "findings", "warnings", "waivers",
	"manifests[].dependencies",
	"manifests[].dependencies[].depends_on", "manifests[].dependencies[].licenses",
	"packages[].licenses", "packages[].vulnerabilities",
}

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
	// resolved, each with its lean dependency list. Always written, empty
	// as []: see IteratedCollections.
	Manifests []Manifest `json:"manifests"`
	// Packages is the matching-stage registry: one package per package URL,
	// carrying the enrichment. Sorted by package URL. Always written, and
	// each package's licenses and vulnerabilities with it; see Package.
	Packages []*model.Package `json:"packages"`
	// Findings are the audit-stage results, referencing packages by URL.
	// Always written.
	Findings []model.Finding `json:"findings"`
	// AuditSummary counts the findings by severity.
	AuditSummary *AuditSummary `json:"audit_summary,omitempty"`
	// Warnings are the typed detector warnings the run surfaced.
	Warnings []plugin.DetectorWarning `json:"warnings"`
	// Verdict is the policy outcome of the whole run.
	Verdict Verdict `json:"verdict,omitempty"`
	// Policy names the policy the findings were evaluated against.
	Policy *PolicyRef `json:"policy,omitempty"`
	// Waivers are the accepted findings that shaped the verdict.
	Waivers []Waiver `json:"waivers"`
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
	// ImageReference is the container image reference the scan was asked
	// for, as given (repository and tag, or repository and digest); a
	// public identity, unlike a local path, and the one thing that tells
	// two tagged images' records apart. ImageDigest is the digest part
	// when the reference was pinned by one: an identity, where a tag is
	// not.
	ImageReference string `json:"image_reference,omitempty"`
	ImageDigest    string `json:"image_digest,omitempty"`
}

// Normalized returns the subject held to its gate: CommitSHA passes
// plugin.NormalizeCommitSHA, the same gate the execution target applies,
// so a record cannot carry a ref name or a padded hash as a commit; the
// other fields are trimmed.
func (s Subject) Normalized() Subject {
	return Subject{
		Kind:           plugin.ExecutionTargetKind(strings.TrimSpace(string(s.Kind))),
		RepositoryURL:  strings.TrimSpace(s.RepositoryURL),
		Ref:            strings.TrimSpace(s.Ref),
		CommitSHA:      plugin.NormalizeCommitSHA(s.CommitSHA),
		ImageReference: strings.TrimSpace(s.ImageReference),
		ImageDigest:    strings.TrimSpace(s.ImageDigest),
	}
}

// subjectWire is the codec's shape: the same fields without the methods,
// so the gate runs once on each direction without recursing.
type subjectWire Subject

// MarshalJSON writes the gated form.
func (s Subject) MarshalJSON() ([]byte, error) {
	return json.Marshal(subjectWire(s.Normalized()))
}

// UnmarshalJSON reads through the gate.
func (s *Subject) UnmarshalJSON(data []byte) error {
	var wire subjectWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	*s = Subject(wire).Normalized()
	return nil
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
	// Document carries what the source SBOM said about itself when the
	// manifest is an ingested document -- identity, version, checksum,
	// creators, data license, format -- so a record restates the document's
	// provenance rather than only its contents. Gated by its own codec.
	Document     *model.DocumentAssertions `json:"document,omitempty"`
	Dependencies []Dependency              `json:"dependencies"`
}

// manifestWire is the codec's shape: the same fields without the methods.
type manifestWire Manifest

// MarshalJSON writes the dependency list even when it is empty.
func (m Manifest) MarshalJSON() ([]byte, error) {
	m.Dependencies = emptyIfNil(m.Dependencies)
	return json.Marshal(manifestWire(m))
}

// Dependency is the lean projection of a graph node: identity, scope, edges,
// and the detection-time facts a manifest states. Enrichment lives once, on
// the package PackageRef names.
type Dependency struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	// Source is where the dependency was resolved from -- a registry, Git,
	// a URL, a file, a workspace -- as the detector recorded it; a change
	// between scans is a review-worthy transition the comparison reports.
	Source model.DependencySource `json:"source,omitempty"`
	// Relationship is whether the dependency was declared directly by its
	// manifest or reached through another, as the detector recorded it. A
	// record lists no manifest nodes, so a comparison rebuilt from one has
	// no structural root to derive this from; the stated value stands in,
	// and the graph comparison honors a stated relationship over a derived
	// one.
	Relationship model.DependencyRelationship `json:"relationship,omitempty"`
	Scopes       []model.Scope                `json:"scopes,omitempty"`
	DependsOn    []string                     `json:"depends_on"`
	Matched      bool                         `json:"matched,omitempty"`
	PackageRef   string                       `json:"package_ref,omitempty"`
	Locations    []model.PackageLocation      `json:"locations,omitempty"`
	Licenses     []model.PackageLicense       `json:"licenses"`
}

// Normalized returns the dependency held to its gate: Relationship passes
// model.ParseDependencyRelationship, so a value outside the vocabulary --
// which the graph comparison would otherwise take as a stated relationship
// and report against the canonical one -- is cleared rather than carried.
func (d Dependency) Normalized() Dependency {
	d.Relationship = model.ParseDependencyRelationship(string(d.Relationship))
	return d
}

// dependencyWire is the codec's shape: the same fields without the methods,
// so the gate runs once on each direction without recursing.
type dependencyWire Dependency

// MarshalJSON writes the gated form, with its edges and licenses written
// even when empty.
func (d Dependency) MarshalJSON() ([]byte, error) {
	normalized := d.Normalized()
	normalized.DependsOn = emptyIfNil(normalized.DependsOn)
	normalized.Licenses = emptyIfNil(normalized.Licenses)
	return json.Marshal(dependencyWire(normalized))
}

// UnmarshalJSON reads through the gate. The wire value starts from the
// receiver, as encoding/json's default decoding would, so a partial object
// applied to an existing dependency keeps the fields it does not name.
func (d *Dependency) UnmarshalJSON(data []byte) error {
	wire := dependencyWire(*d)
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	*d = Dependency(wire).Normalized()
	return nil
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

// recordWire is the record as it is written: the same fields in the same
// order, with each package encoded as a Package so its iterated
// collections are written too. TestRecordWireMirrorsRecord keeps the two
// field lists from drifting.
type recordWire struct {
	SchemaVersion string                   `json:"schema_version"`
	Command       string                   `json:"command,omitempty"`
	Subject       Subject                  `json:"subject,omitzero"`
	Run           Run                      `json:"run,omitzero"`
	Manifests     []Manifest               `json:"manifests"`
	Packages      []Package                `json:"packages"`
	Findings      []model.Finding          `json:"findings"`
	AuditSummary  *AuditSummary            `json:"audit_summary,omitempty"`
	Warnings      []plugin.DetectorWarning `json:"warnings"`
	Verdict       Verdict                  `json:"verdict,omitempty"`
	Policy        *PolicyRef               `json:"policy,omitempty"`
	Waivers       []Waiver                 `json:"waivers"`
	Metadata      Metadata                 `json:"metadata,omitzero"`
	Digests       *SectionDigests          `json:"digests,omitempty"`
}

// MarshalJSON writes the record with its iterated collections present even
// when empty. Encode is the canonical writer; this is what makes a record
// marshaled directly take the same shape.
func (r Record) MarshalJSON() ([]byte, error) {
	return json.Marshal(recordWire{
		SchemaVersion: r.SchemaVersion,
		Command:       r.Command,
		Subject:       r.Subject,
		Run:           r.Run,
		Manifests:     emptyIfNil(r.Manifests),
		Packages:      packagesOf(r.Packages),
		Findings:      emptyIfNil(r.Findings),
		AuditSummary:  r.AuditSummary,
		Warnings:      emptyIfNil(r.Warnings),
		Verdict:       r.Verdict,
		Policy:        r.Policy,
		Waivers:       emptyIfNil(r.Waivers),
		Metadata:      r.Metadata,
		Digests:       r.Digests,
	})
}

// Package is a registry package as a document writes it: the SDK package,
// gated by its own rules, with its licenses and vulnerabilities written as
// [] when it has none. model.Package omits them, because on the plugin
// wire every field is optional by contract; a document a consumer iterates
// is held to IteratedCollections instead, so this type carries that shape
// for the record and for any other document built from the same packages.
type Package struct {
	*model.Package
}

// packageBody is model.Package without its methods, so its fields encode
// by the standard rules underneath the two collections Package overrides.
type packageBody model.Package

// packageWire puts the two iterated collections at the top level, where
// they take precedence over the same keys inside the embedded package.
type packageWire struct {
	packageBody
	Licenses        []model.PackageLicense `json:"licenses"`
	Vulnerabilities []model.Vulnerability  `json:"vulnerabilities"`
}

// MarshalJSON writes the package through the same gate model.Package's own
// codec applies, then with its licenses and vulnerabilities always present.
// The holder's package is not edited.
func (p Package) MarshalJSON() ([]byte, error) {
	if p.Package == nil {
		return []byte("null"), nil
	}
	gated := *p.Package
	gated.Vulnerabilities = append([]model.Vulnerability(nil), gated.Vulnerabilities...)
	gated.NormalizeAssertions()
	return json.Marshal(packageWire{
		packageBody:     packageBody(gated),
		Licenses:        emptyIfNil(gated.Licenses),
		Vulnerabilities: emptyIfNil(gated.Vulnerabilities),
	})
}

// UnmarshalJSON reads a package through model.Package's own codec. Without
// it, decoding into a zero Package would call the embedded pointer's
// unmarshaler with that pointer still nil and panic; a document type that
// is exported must read untrusted JSON safely. null leaves the package nil.
//
// The input is bounded before it is parsed, as every untrusted parser here
// is: a package read on its own, outside Decode, does not inherit the
// record's byte bound, so it applies the same one -- one package can be no
// larger than the record that would hold it.
func (p *Package) UnmarshalJSON(data []byte) error {
	if len(data) > recordBounds.bytes {
		return fmt.Errorf("%w: package of %d bytes, over %d", ErrRecordTooLarge, len(data), recordBounds.bytes)
	}
	if string(bytes.TrimSpace(data)) == "null" {
		p.Package = nil
		return nil
	}
	decoded := new(model.Package)
	if err := json.Unmarshal(data, decoded); err != nil {
		return err
	}
	p.Package = decoded
	return nil
}

// Packages wraps registry packages for a document, so each one writes its
// iterated collections. Nil packages are kept as they are.
func Packages(packages []*model.Package) []Package {
	return packagesOf(packages)
}

func packagesOf(packages []*model.Package) []Package {
	out := make([]Package, 0, len(packages))
	for _, pkg := range packages {
		out = append(out, Package{pkg})
	}
	return out
}

// emptyIfNil returns values, or an empty slice in place of nil, so a
// collection without omitempty is written as [] rather than null.
func emptyIfNil[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}
