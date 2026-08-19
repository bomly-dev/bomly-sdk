package sdk

import (
	"sort"
	"strings"
)

// PackageType describes the broad role or artifact kind of a package node.
type PackageType string

const (
	PackageTypeUnknown     PackageType = ""
	PackageTypeApplication PackageType = "application"
	PackageTypePackage     PackageType = "package"
	PackageTypeManifest    PackageType = "manifest"
	PackageTypeWorkflow    PackageType = "workflow"
	PackageTypeAction      PackageType = "action"
	PackageTypeTransitive  PackageType = "transitive"
	PackageTypeProject     PackageType = "project"
	PackageTypeFile        PackageType = "file"
)

// ParsePackageType normalizes a package role string.
func ParsePackageType(value string) PackageType {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return PackageTypeUnknown
	}
	return PackageType(normalized)
}

// String returns the package type value.
func (t PackageType) String() string { return string(t) }

// LicenseType identifies license provenance.
type LicenseType string

const (
	LicenseTypeDeclared LicenseType = "declared"
)

// DigestAlgorithm identifies an artifact digest algorithm.
type DigestAlgorithm string

const (
	DigestAlgorithmSHA1   DigestAlgorithm = "sha1"
	DigestAlgorithmSHA256 DigestAlgorithm = "sha256"
)

// PackageLocation captures where a package was discovered.
type PackageLocation struct {
	RealPath   string `json:"real_path,omitempty"`
	AccessPath string `json:"access_path,omitempty"`
	// Position optionally points at the exact line / column in RealPath where
	// the package is declared. nil when unknown.
	Position *SourcePosition `json:"position,omitempty"`
}

// PackageLicense captures normalized license details for a package.
type PackageLicense struct {
	Value          string      `json:"value,omitempty"`
	SPDXExpression string      `json:"spdx_expression,omitempty"`
	Type           LicenseType `json:"type,omitempty"`
}

// Digest captures integrity information for a package artifact.
type Digest struct {
	Algorithm DigestAlgorithm `json:"algorithm,omitempty"`
	Value     string          `json:"value,omitempty"`
	// Subject says what the digest covers. Empty means the published artifact,
	// which is what most ecosystems record and what a consumer should assume.
	// It exists because some ecosystems record a hash that is not a hash of a
	// file: a Go module's "h1:" value is SHA-256 over a manifest of the source
	// tree's file hashes, not over the module zip, so a consumer that treats it
	// as an artifact digest and compares it against a downloaded file will
	// always find a mismatch.
	Subject DigestSubject `json:"subject,omitempty"`
}

// DigestSubject identifies what a digest was computed over.
type DigestSubject string

const (
	// DigestSubjectArtifact is a digest of the published file itself. It is
	// the zero value: a producer that does not say means the artifact.
	DigestSubjectArtifact DigestSubject = ""
	// DigestSubjectSourceTree is a digest over a source tree or over a
	// manifest of its file hashes, such as a Go module "h1:" dirhash.
	DigestSubjectSourceTree DigestSubject = "source-tree"
	// DigestSubjectMetadata is a digest of a package's metadata document
	// rather than of the package itself, such as a manifest or lockfile entry.
	DigestSubjectMetadata DigestSubject = "metadata"
)

// PackageAttestation records a signed statement about how a package was built
// or published: an in-toto statement such as SLSA provenance, or a
// publish-time signature.
//
// Bomly does not fetch or verify attestations today. The type exists so a
// matcher that does can attach what it found without a model change, and so
// consumers can tell a verified statement from one that was merely present --
// a distinction that matters more than the statement itself, and that is
// easily lost when provenance data is carried in untyped metadata.
type PackageAttestation struct {
	// PredicateType identifies what the statement asserts, using the in-toto
	// predicate vocabulary (for example "https://slsa.dev/provenance/v1").
	PredicateType string `json:"predicate_type,omitempty"`
	// Source names the component or service that attached the statement, in
	// the same style as PackageScorecard.Source.
	Source string `json:"source,omitempty"`
	// URL is where the statement can be fetched.
	URL string `json:"url,omitempty"`
	// Digest identifies the statement itself, so two fetches of one URL can be
	// told apart.
	Digest *Digest `json:"digest,omitempty"`
	// Issuer is the identity that signed the statement -- an OIDC identity, a
	// key id, or a registry account -- as reported by whatever verified it.
	Issuer string `json:"issuer,omitempty"`
	// Verified records that the component attaching this statement checked its
	// signature. False means the statement was found but not verified, which is
	// weaker evidence rather than evidence of tampering; consumers must not
	// present an unverified statement as proof of provenance.
	Verified bool `json:"verified,omitempty"`
}

// mergeAttestations folds incoming statements into p, keeping one record per
// distinct statement. Several components can attest to one package -- a build
// provenance statement from one, a publish signature from another -- so this
// unions rather than keeping whichever arrived first, the way vulnerabilities
// already do. When two records describe the same statement and either verified
// it, the merged record is verified: verification is a fact one component
// established, not an opinion.
func (p *Package) mergeAttestations(incoming []PackageAttestation) {
	if len(incoming) == 0 {
		return
	}
	for _, candidate := range incoming {
		merged := false
		for i := range p.Attestations {
			if !p.Attestations[i].describesSame(candidate) {
				continue
			}
			p.Attestations[i].absorb(candidate)
			merged = true
			break
		}
		if !merged {
			p.Attestations = append(p.Attestations, candidate.Clone())
		}
	}
}

// describesSame reports whether two records can be folded into one. Verification
// is a fact about a statement *and a signer*, so records fold only when they
// agree on the issuer -- or when one of them claims nothing that could be
// misattributed.
//
// A record with no issuer and no verification says only that the statement
// exists, which any other record for it already says, so it folds into
// anything. A record with no issuer that *was* verified is a real claim ("this
// was verified, signer unrecorded") and stays separate from a record naming an
// issuer: merging them would report that issuer as verified on the strength of
// a verification that may have been of someone else's signature.
func (a PackageAttestation) describesSame(other PackageAttestation) bool {
	if a.key() != other.key() {
		return false
	}
	switch {
	case a.Issuer == other.Issuer:
		return true
	case a.claimsNothing(), other.claimsNothing():
		return true
	default:
		return false
	}
}

// claimsNothing reports whether a asserts anything beyond the statement's
// existence.
func (a PackageAttestation) claimsNothing() bool {
	return a.Issuer == "" && !a.Verified
}

// absorb folds a record describing the same statement into a. Verification
// never moves between issuers: it travels only when this record claims nothing,
// in which case the other record replaces it wholesale.
func (a *PackageAttestation) absorb(other PackageAttestation) {
	switch {
	case a.claimsNothing():
		*a = other.Clone()
	case other.claimsNothing():
		// Nothing to take.
	case other.Verified:
		// Same issuer, so the verification is this issuer's.
		a.Verified = true
	}
}

// attestationKey identifies one statement for deduplication. Issuer is
// deliberately absent: it is compared separately, because an unknown issuer is
// compatible with a known one while two known issuers are not.
type attestationKey struct {
	source        string
	predicateType string
	url           string
	digest        string
}

// key returns a's deduplication identity.
func (a PackageAttestation) key() attestationKey {
	key := attestationKey{source: a.Source, predicateType: a.PredicateType, url: a.URL}
	if a.Digest != nil {
		// Subject is part of the identity: the same bytes hashed over a
		// source tree and over an artifact are different claims.
		key.digest = string(a.Digest.Algorithm) + ":" + a.Digest.Value + ":" + string(a.Digest.Subject)
	}
	return key
}

// Clone returns a deep copy.
func (a PackageAttestation) Clone() PackageAttestation {
	clone := a
	if a.Digest != nil {
		digest := *a.Digest
		clone.Digest = &digest
	}
	return clone
}

// PackageEOL captures end-of-life enrichment attached by the EOL matcher.
type PackageEOL struct {
	Source        string `json:"source,omitempty"`
	Cycle         string `json:"cycle,omitempty"`
	EOL           bool   `json:"eol,omitempty"`
	EOLDate       string `json:"eol_date,omitempty"`
	LatestVersion string `json:"latest_version,omitempty"`
	ReleaseDate   string `json:"release_date,omitempty"`
	Supported     bool   `json:"supported,omitempty"`
}

// Clone returns a deep copy of the EOL payload.
func (e *PackageEOL) Clone() *PackageEOL {
	if e == nil {
		return nil
	}
	return new(*e)
}

// PackageRemediationStatus describes how completely vulnerability enrichment
// identifies a safe package version.
type PackageRemediationStatus string

const (
	// PackageRemediationComplete means every vulnerability has usable fix
	// evidence and one recommended package version can address all of them.
	PackageRemediationComplete PackageRemediationStatus = "complete"
	// PackageRemediationPartial means fix evidence exists, but it cannot produce
	// one complete package recommendation.
	PackageRemediationPartial PackageRemediationStatus = "partial"
	// PackageRemediationUnavailable means every vulnerability explicitly reports
	// that no fix is available.
	PackageRemediationUnavailable PackageRemediationStatus = "unavailable"
	// PackageRemediationUnknown means fix evidence is missing or contradictory.
	PackageRemediationUnknown PackageRemediationStatus = "unknown"
)

// RemediationAction identifies the user action suggested for one or more
// occurrences of an enriched vulnerable package.
type RemediationAction string

const (
	// RemediationActionDirectBump suggests updating a directly declared package.
	RemediationActionDirectBump RemediationAction = "direct-bump"
	// RemediationActionTransitiveOverride suggests using a package-manager
	// override for a transitive package.
	RemediationActionTransitiveOverride RemediationAction = "transitive-override"
	// RemediationActionLockfileRefresh suggests asking the package manager to
	// resolve a newer transitive package version.
	RemediationActionLockfileRefresh RemediationAction = "lockfile-refresh"
	// RemediationActionNoFixUpstream reports that every vulnerability explicitly
	// lacks an upstream fix.
	RemediationActionNoFixUpstream RemediationAction = "no-fix-upstream"
	// RemediationActionManualReview reports that available evidence cannot
	// support a safe, concrete automated suggestion.
	RemediationActionManualReview RemediationAction = "manual-review"
)

// PackageRemediationSuggestion describes one occurrence-scoped action for the
// containing package. AffectedDependencyRefs identify occurrences of the
// vulnerable package. SuggestedActionDependencyRef identifies the direct
// dependency or manifest anchor the suggested action targets.
type PackageRemediationSuggestion struct {
	AffectedDependencyRefs       []string          `json:"affected_dependency_refs"`
	SuggestedActionDependencyRef string            `json:"suggested_action_dependency_ref,omitempty"`
	ManifestPath                 string            `json:"manifest_path,omitempty"`
	Action                       RemediationAction `json:"action"`
	OverrideAdvice               string            `json:"override_advice,omitempty"`
}

// PackageRemediation summarizes the fix evidence already present on a
// package's enriched vulnerabilities.
type PackageRemediation struct {
	Status             PackageRemediationStatus       `json:"status"`
	RecommendedVersion string                         `json:"recommended_version,omitempty"`
	Suggestions        []PackageRemediationSuggestion `json:"suggestions,omitempty"`
}

// Clone returns a copy of the package remediation summary.
func (r *PackageRemediation) Clone() *PackageRemediation {
	if r == nil {
		return nil
	}
	clone := *r
	if len(r.Suggestions) > 0 {
		clone.Suggestions = make([]PackageRemediationSuggestion, len(r.Suggestions))
		for idx, suggestion := range r.Suggestions {
			clone.Suggestions[idx] = suggestion
			clone.Suggestions[idx].AffectedDependencyRefs = cloneStrings(suggestion.AffectedDependencyRefs)
		}
	}
	return &clone
}

// Package describes one matching artifact: the PURL-keyed, deduplicated record
// produced by the matching stage. Many Dependency nodes (across manifests and
// subprojects) reference a single Package by PURL. A Package holds only
// matching-stage enrichment; detection-time identity and relationships live on
// Dependency.
type Package struct {
	Coordinates
	// ID is the package registry identifier. It may be a database ID, PURL, or
	// another stable key chosen by the package registry.
	ID          string `json:"id,omitempty"`
	Copyright   string `json:"copyright,omitempty"`
	ResolvedURL string `json:"resolved_url,omitempty"`
	// Origin is where this package came from: carried from the dependency that
	// referenced it, or resolved by a matcher. Read it through
	// Origin.Normalized().
	Origin *PackageOrigin `json:"origin,omitempty"`

	CPEs            []string             `json:"cpes,omitempty"`
	Digests         []Digest             `json:"digests,omitempty"`
	Licenses        []PackageLicense     `json:"licenses,omitempty"`
	Vulnerabilities []Vulnerability      `json:"vulnerabilities,omitempty"`
	Attestations    []PackageAttestation `json:"attestations,omitempty"`
	Scorecard       *PackageScorecard    `json:"scorecard,omitempty"`
	EOL             *PackageEOL          `json:"eol,omitempty"`
	Remediation     *PackageRemediation  `json:"remediation,omitempty"`

	// Matched indicates that this package was successfully matched by one or
	// more external enrichment sources.
	Matched bool `json:"matched,omitempty"`

	// Metadata holds per-ecosystem extensible data.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// MetadataKeyNPM is the Metadata map key for *NPMPackageMetadata.
const MetadataKeyNPM = "npm"

// MetadataKeyDetectionLicenses is the Dependency.Metadata key under which
// detectors that discover license facts at detection time (e.g. SBOM-backed
// detectors) stash []PackageLicense for consolidation to lift into the
// package registry.
const MetadataKeyDetectionLicenses = "bomly.detection.licenses"

// NPMPackageMetadata holds npm-specific package data extracted from npm/pnpm/yarn
// lockfiles that does not fit into the cross-ecosystem fields.
type NPMPackageMetadata struct {
	Bundled                  bool              `json:"bundled,omitempty"`
	Extraneous               bool              `json:"extraneous,omitempty"`
	HasInstallScript         bool              `json:"hasInstallScript,omitempty"`
	PeerDependencies         map[string]string `json:"peerDependencies,omitempty"`
	OptionalPeerDependencies []string          `json:"optionalPeerDependencies,omitempty"`
	Engines                  map[string]string `json:"engines,omitempty"`
}

// QualifiedName returns the package name prefixed with its organization when present.
func (p *Package) QualifiedName() string {
	if p == nil {
		return ""
	}
	return p.Coordinates.QualifiedName()
}

// DisplayName returns the most human-friendly identifier available, using
// the ecosystem-native name form (e.g. "@org/name" for npm).
func (p *Package) DisplayName() string {
	if p == nil {
		return ""
	}
	if name := p.Coordinates.DisplayName(); name != "" {
		return name
	}
	return p.PURL
}

// IdentityKey returns a stable package identity without version information.
func (p *Package) IdentityKey() string {
	if p == nil {
		return ""
	}
	return p.Coordinates.IdentityKey()
}

// LicenseValues returns normalized package license labels in stable order.
func (p *Package) LicenseValues() []string {
	if p == nil || len(p.Licenses) == 0 {
		return nil
	}
	values := make([]string, 0, len(p.Licenses))
	for _, license := range p.Licenses {
		switch {
		case license.SPDXExpression != "":
			values = append(values, license.SPDXExpression)
		case license.Value != "":
			values = append(values, license.Value)
		}
	}
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
	return values
}

// Clone returns a deep copy of the package.
func (p *Package) Clone() *Package {
	if p == nil {
		return nil
	}
	clone := *p
	clone.CPEs = cloneStrings(p.CPEs)
	if len(p.Digests) > 0 {
		clone.Digests = append([]Digest(nil), p.Digests...)
	}
	if len(p.Licenses) > 0 {
		clone.Licenses = append([]PackageLicense(nil), p.Licenses...)
	}
	if len(p.Vulnerabilities) > 0 {
		clone.Vulnerabilities = make([]Vulnerability, 0, len(p.Vulnerabilities))
		for _, v := range p.Vulnerabilities {
			clone.Vulnerabilities = append(clone.Vulnerabilities, v.Clone())
		}
	}
	clone.Origin = p.Origin.Clone()
	if len(p.Attestations) > 0 {
		clone.Attestations = make([]PackageAttestation, 0, len(p.Attestations))
		for _, attestation := range p.Attestations {
			clone.Attestations = append(clone.Attestations, attestation.Clone())
		}
	}
	clone.Scorecard = p.Scorecard.Clone()
	clone.EOL = p.EOL.Clone()
	clone.Remediation = p.Remediation.Clone()
	clone.Metadata = cloneAnyMap(p.Metadata)
	return &clone
}

// MergeFrom folds enrichment from src into p in place. Used by the package
// registry to deduplicate multiple records for the same PURL. Existing typed
// data on p wins; src contributes anything p is missing, and vulnerability
// lists are unioned by (Source, ID).
func (p *Package) MergeFrom(src *Package) {
	if p == nil || src == nil {
		return
	}
	if p.ID == "" {
		p.ID = src.ID
	}
	if p.Ecosystem == "" {
		p.Ecosystem = src.Ecosystem
	}
	if p.Name == "" {
		p.Name = src.Name
	}
	if p.Version == "" {
		p.Version = src.Version
	}
	if p.Org == "" {
		p.Org = src.Org
	}
	if p.Type == PackageTypeUnknown {
		p.Type = src.Type
	}
	if p.PackageManager == PackageManagerUnknown {
		p.PackageManager = src.PackageManager
	}
	if p.Language == LanguageUnknown {
		p.Language = src.Language
	}
	if strings.TrimSpace(p.Copyright) == "" {
		p.Copyright = src.Copyright
	}
	if p.ResolvedURL == "" {
		p.ResolvedURL = src.ResolvedURL
	}
	// Two records of one package that disagree about where it came from settle
	// to no origin rather than to whichever was merged first.
	p.Origin = ReconcileOrigin(p.Origin, src.Origin)
	p.mergeAttestations(src.Attestations)
	if len(p.CPEs) == 0 {
		p.CPEs = cloneStrings(src.CPEs)
	}
	if len(p.Digests) == 0 && len(src.Digests) > 0 {
		p.Digests = append([]Digest(nil), src.Digests...)
	}
	if len(p.Licenses) == 0 && len(src.Licenses) > 0 {
		p.Licenses = append([]PackageLicense(nil), src.Licenses...)
	}
	if p.Scorecard == nil {
		p.Scorecard = src.Scorecard.Clone()
	}
	if p.EOL == nil {
		p.EOL = src.EOL.Clone()
	}
	if src.Matched {
		p.Matched = true
	}
	p.mergeVulnerabilities(src.Vulnerabilities)
	if len(src.Metadata) > 0 {
		if p.Metadata == nil {
			p.Metadata = make(map[string]any, len(src.Metadata))
		}
		for k, v := range src.Metadata {
			if _, exists := p.Metadata[k]; !exists {
				p.Metadata[k] = v
			}
		}
	}
}

func (p *Package) mergeVulnerabilities(incoming []Vulnerability) {
	if len(incoming) == 0 {
		return
	}
	idx := make(map[string]int, len(p.Vulnerabilities))
	for i, v := range p.Vulnerabilities {
		idx[v.Source+"\x00"+v.ID] = i
	}
	for _, v := range incoming {
		key := v.Source + "\x00" + v.ID
		if existing, ok := idx[key]; ok {
			dst := &p.Vulnerabilities[existing]
			if dst.Reachability == nil && v.Reachability != nil {
				dst.Reachability = v.Reachability.Clone()
			}
			if len(dst.AffectedSymbols) == 0 && len(v.AffectedSymbols) > 0 {
				dst.AffectedSymbols = make([]AffectedSymbol, 0, len(v.AffectedSymbols))
				for _, sym := range v.AffectedSymbols {
					dst.AffectedSymbols = append(dst.AffectedSymbols, sym.Clone())
				}
			}
			continue
		}
		p.Vulnerabilities = append(p.Vulnerabilities, v.Clone())
		idx[key] = len(p.Vulnerabilities) - 1
	}
}

// SetDetectionLicenses stashes detection-time license facts on dep's metadata
// under MetadataKeyDetectionLicenses, so consolidation can lift them into the
// package registry. No-op when dep is nil or licenses is empty.
func SetDetectionLicenses(dep *Dependency, licenses []PackageLicense) {
	if dep == nil || len(licenses) == 0 {
		return
	}
	if dep.Metadata == nil {
		dep.Metadata = make(map[string]any, 1)
	}
	dep.Metadata[MetadataKeyDetectionLicenses] = licenses
}

// DetectionLicenses returns license facts stashed on dep at detection time.
func DetectionLicenses(dep *Dependency) []PackageLicense {
	if dep == nil || dep.Metadata == nil {
		return nil
	}
	if v, ok := dep.Metadata[MetadataKeyDetectionLicenses].([]PackageLicense); ok {
		return v
	}
	return nil
}

// PackageFromDependency seeds a registry package from a dependency's identity
// fields. The returned package carries no enrichment; matchers fill it in.
func PackageFromDependency(dep *Dependency) *Package {
	if dep == nil {
		return nil
	}
	purl := CanonicalPackageURLFromDependency(dep)
	return &Package{
		Coordinates: Coordinates{
			PURL:           purl,
			Ecosystem:      dep.Ecosystem,
			Name:           dep.Name,
			Version:        dep.Version,
			Org:            dep.Org,
			Type:           dep.Type,
			PackageManager: dep.PackageManager,
			Language:       dep.Language,
		},
		ID:          purl,
		ResolvedURL: dep.ResolvedURL,
		Origin:      dep.Origin.Clone(),
	}
}

func qualifiedName(org, name string) string {
	if org == "" {
		return name
	}
	if name == "" {
		return org
	}
	return org + ":" + name
}
