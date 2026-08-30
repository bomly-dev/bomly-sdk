package sdk

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-sdk/spdxkit"
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

// LicenseType identifies license provenance: who is making the claim. Both
// SBOM formats draw the same distinction -- SPDX as licenseDeclared versus
// licenseConcluded, CycloneDX 1.6 as the acknowledgement field -- and it
// matters to a reader, because a declared license is what the package says
// about itself while a concluded one is what an analysis decided after
// looking. Collapsing them, as a single-valued vocabulary does, publishes an
// opinion as if the package had stated it.
type LicenseType string

const (
	// LicenseTypeDeclared is the license the package declares about itself:
	// a manifest field, a registry record, a lockfile entry.
	LicenseTypeDeclared LicenseType = "declared"
	// LicenseTypeConcluded is the license an analysis concluded, having
	// looked at more than the declaration -- a license file's text, a scan
	// result, a human review. It may contradict the declaration, which is a
	// fact worth publishing rather than a conflict to resolve.
	LicenseTypeConcluded LicenseType = "concluded"
)

// ParseLicenseType normalizes a license provenance value. An empty value is
// unknown provenance, which is legal; anything else unrecognized is an error,
// since a misspelled provenance would silently publish a conclusion as a
// declaration.
func ParseLicenseType(value string) (LicenseType, error) {
	switch LicenseType(strings.ToLower(strings.TrimSpace(value))) {
	case "":
		return "", nil
	case LicenseTypeDeclared:
		return LicenseTypeDeclared, nil
	case LicenseTypeConcluded:
		return LicenseTypeConcluded, nil
	default:
		return "", fmt.Errorf("unsupported license type %q", value)
	}
}

// DigestAlgorithm identifies an artifact digest algorithm. The vocabulary is
// the registry in digest.go, aligned with the SPDX 2.3 and CycloneDX 1.5/1.6
// hash vocabularies; see DigestAlgorithms.
type DigestAlgorithm string

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
	// Value is the license as the source stated it, unmodified.
	Value string `json:"value,omitempty"`
	// SPDXExpression is the validated SPDX expression form, when the value
	// has one. For a license that is not on the SPDX list, this is a minted
	// LicenseRef-* identifier whose text is carried in ExtractedText.
	SPDXExpression string `json:"spdx_expression,omitempty"`
	// Type is who made the claim; see LicenseType.
	Type LicenseType `json:"type,omitempty"`
	// Name is the human-readable license name for a LicenseRef-* identifier.
	// SPDX's hasExtractedLicensingInfos carries one, and a reader given only
	// "LicenseRef-bomly-3f2a..." has nothing to go on.
	Name string `json:"name,omitempty"`
	// ExtractedText is the original license text a LicenseRef-* identifier
	// names. Both formats require the text to accompany the reference -- an
	// SPDX document whose expression cites a LicenseRef without a matching
	// hasExtractedLicensingInfos entry is invalid -- so the pair travels
	// together on one record rather than in a side table that a merge or a
	// projection could separate it from (bomly-cli issue #410).
	//
	// The text is authoritative and the reference is derived from it, per
	// spdxkit.MintLicenseRef. Normalized re-mints rather than trusting a
	// reference that disagrees with its text.
	ExtractedText string `json:"extracted_text,omitempty"`
}

// maxExtractedLicenseTextLength bounds carried license text. Long licenses run
// to a few tens of kilobytes; the allowance covers them with room to spare
// while keeping a hostile document from carrying a megabyte of text per
// component through the plugin wire.
const maxExtractedLicenseTextLength = 128 * 1024

// Normalized returns the license with its claim re-checked, or false when the
// record says nothing publishable. It is the gate for a license that arrived
// from a plugin, an ingested document, or a hand-built value.
//
// Three rules are enforced. An unrecognized provenance is dropped to unknown
// rather than published as a claim nobody made. A LicenseRef-* expression is
// re-minted from its text, since spdxkit makes the text authoritative: a
// reference that disagrees with the text it names would produce a document
// whose citation resolves to the wrong license. And every other expression is
// put to spdxkit -- the single home for SPDX expression semantics (ADR-0038) --
// rather than trusted because it merely lacks a reference prefix.
//
// The expression that survives is the canonical one. spdxkit rewrites
// deprecated identifiers, so "GPL-2.0" is stored as "GPL-2.0-only": Value keeps
// what the source said, while SPDXExpression is the form Bomly is willing to
// publish. Anything the parser rejects is dropped rather than exported into a
// document that would then fail its own validator.
func (l PackageLicense) Normalized() (PackageLicense, bool) {
	normalized := PackageLicense{
		Value:          strings.TrimSpace(l.Value),
		SPDXExpression: strings.TrimSpace(l.SPDXExpression),
		Name:           strings.TrimSpace(l.Name),
		ExtractedText:  l.ExtractedText,
	}
	if licenseType, err := ParseLicenseType(string(l.Type)); err == nil {
		normalized.Type = licenseType
	}
	// Whitespace-only text is not text. It would otherwise mint the reference
	// that empty text mints and publish a citation whose licensing entry says
	// nothing -- a document that does not validate and, worse, one where
	// every package with blank text shares one reference.
	if len(normalized.ExtractedText) > maxExtractedLicenseTextLength || strings.TrimSpace(normalized.ExtractedText) == "" {
		normalized.ExtractedText = ""
	}
	if strings.HasPrefix(normalized.SPDXExpression, spdxkit.LicenseRefPrefix) {
		switch {
		case strings.TrimSpace(normalized.ExtractedText) == "":
			// A reference with no text cannot be published: the citation
			// would dangle and the document would not validate. The stated
			// value survives on its own.
			normalized.SPDXExpression = ""
			normalized.Name = ""
		case strings.HasPrefix(normalized.SPDXExpression, spdxkit.BomlyLicenseRefPrefix):
			// Bomly's own references are derived from their text, so a
			// disagreement is repaired by re-minting rather than trusted.
			normalized.SPDXExpression = spdxkit.MintLicenseRef(normalized.ExtractedText).RefID
		case !spdxkit.ValidLicenseRef(normalized.SPDXExpression):
			// A source-defined reference that is not a well-formed idstring
			// cannot go into an expression field verbatim. Re-mint under
			// Bomly's prefix so the text still travels with a citation.
			normalized.SPDXExpression = spdxkit.MintLicenseRef(normalized.ExtractedText).RefID
		default:
			// A well-formed reference the source document defined is kept as
			// stated, so re-exporting that document reproduces its own
			// identifiers instead of renaming them.
		}
	} else if normalized.SPDXExpression != "" {
		normalized.SPDXExpression = normalizedSPDXExpression(normalized.SPDXExpression, normalized.ExtractedText)
	}
	// Text that ended up with no citation gets one, whether the expression
	// arrived empty or was just dropped as unpublishable: text nothing can
	// cite is text that will be lost on export.
	//
	// This has to happen after the checks above, not only in the
	// arrived-empty case. Minting solely for an empty input meant a value
	// whose expression was rejected acquired its reference on the *second*
	// pass instead of the first, so normalizing twice gave a different
	// answer -- and Normalized runs on both marshal and unmarshal, so the
	// same record would have changed shape each time it crossed the wire.
	if normalized.SPDXExpression == "" && normalized.ExtractedText != "" {
		normalized.SPDXExpression = spdxkit.MintLicenseRef(normalized.ExtractedText).RefID
	}
	if normalized.Value == "" && normalized.SPDXExpression == "" {
		return PackageLicense{}, false
	}
	return normalized, true
}

// normalizedSPDXExpression puts a general expression -- one that is not itself
// a bare license reference -- to spdxkit, returning the canonical form or ""
// when the parser rejects it.
//
// This exists because "does not start with LicenseRef-" is not evidence that a
// string is a license expression. A value like "not valid OR" would otherwise
// be stored as a typed claim, merged as one, and exported into a document that
// fails its own validator, with the failure surfacing far from the component
// that carried it.
//
// A compound expression may still name a reference ("MIT OR LicenseRef-Acme").
// The parser accepts those, but a citation without its text is exactly the
// dangling reference the bare-reference branch refuses, so the same rule
// applies here: no text, no expression.
func normalizedSPDXExpression(expression, extractedText string) string {
	if strings.Contains(expression, spdxkit.LicenseRefPrefix) && strings.TrimSpace(extractedText) == "" {
		return ""
	}
	// Canonicalize first, then validate what would actually be published: a
	// rewrite that produced an invalid expression must not survive on the
	// strength of its input having been valid.
	canonical := spdxkit.CanonicalExpression(expression)
	if !spdxkit.Valid(canonical) {
		return ""
	}
	return canonical
}

// licenseKey is the merge identity of a license claim: the same expression
// asserted as declared and as concluded are two claims, not a duplicate.
//
// The text takes part in the identity, by its minted reference rather than by
// its bytes. Source-defined references are document-local -- two SBOMs can
// each define "LicenseRef-Custom" for entirely different terms -- so a key
// without the text would call those one claim and silently drop the second
// document's license text. Keying on the mint keeps the map small while
// keeping distinct texts distinct.
func (l PackageLicense) licenseKey() string {
	textKey := ""
	if strings.TrimSpace(l.ExtractedText) != "" {
		textKey = spdxkit.MintLicenseRef(l.ExtractedText).RefID
	}
	return string(l.Type) + "\x00" + l.SPDXExpression + "\x00" + l.Value + "\x00" + textKey
}

// MergeLicenses unions license claims, keeping the first record of each
// distinct claim. Licenses are a set: a package whose declaration and whose
// concluded analysis disagree carries both, and two sources that saw the same
// declaration contribute one entry.
func MergeLicenses(existing, additions []PackageLicense) []PackageLicense {
	if len(additions) == 0 {
		return existing
	}
	merged := make([]PackageLicense, 0, len(existing)+len(additions))
	seen := make(map[string]struct{}, len(existing)+len(additions))
	// textByRef records which text each surviving reference names, so a second
	// claim reusing that reference for different terms can be spotted.
	textByRef := make(map[string]string, len(existing)+len(additions))
	for _, group := range [][]PackageLicense{existing, additions} {
		for _, license := range group {
			normalized, ok := license.Normalized()
			if !ok {
				continue
			}
			normalized = resolveLicenseRefCollision(normalized, textByRef)
			key := normalized.licenseKey()
			if _, found := seen[key]; found {
				continue
			}
			seen[key] = struct{}{}
			merged = append(merged, normalized)
		}
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}

// resolveLicenseRefCollision keeps a merged license set unambiguous when two
// sources use one reference for different terms.
//
// A source-defined reference is document-local: preserving it (so re-exporting
// a document reproduces its own identifiers) means two documents can each
// arrive naming "LicenseRef-Custom" for unrelated licenses. Merging them into
// one set would leave that identifier naming two texts, which is not a valid
// document in either format, and a reader would see whichever entry the
// exporter happened to write.
//
// The first claim to use a reference keeps it. A later claim that reuses it
// for different text is re-minted under Bomly's prefix, which is derived from
// its own text and so cannot collide again. The contradiction survives as two
// distinct, citable claims rather than being resolved by dropping one.
func resolveLicenseRefCollision(license PackageLicense, textByRef map[string]string) PackageLicense {
	text := strings.TrimSpace(license.ExtractedText)
	if text == "" || !strings.HasPrefix(license.SPDXExpression, spdxkit.LicenseRefPrefix) {
		return license
	}
	prior, seen := textByRef[license.SPDXExpression]
	switch {
	case !seen:
		textByRef[license.SPDXExpression] = text
	case prior != text:
		license.SPDXExpression = spdxkit.MintLicenseRef(license.ExtractedText).RefID
		textByRef[license.SPDXExpression] = text
	}
	return license
}

// packageLicenseWire carries PackageLicense's fields without its methods, so
// the JSON hooks below can encode and decode without recursing.
type packageLicenseWire PackageLicense

// UnmarshalJSON applies the license rule as a value arrives, so a claim that
// would be rejected on read cannot be stored, forwarded, or written back out.
// A record that says nothing publishable decodes to the zero value, following
// DependencyOrigin.
func (l *PackageLicense) UnmarshalJSON(data []byte) error {
	var wire packageLicenseWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	normalized, ok := PackageLicense(wire).Normalized()
	if !ok {
		*l = PackageLicense{}
		return nil
	}
	*l = normalized
	return nil
}

// MarshalJSON applies the same rule on the way out.
func (l PackageLicense) MarshalJSON() ([]byte, error) {
	normalized, ok := l.Normalized()
	if !ok {
		return json.Marshal(packageLicenseWire{})
	}
	return json.Marshal(packageLicenseWire(normalized))
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
	ID        string `json:"id,omitempty"`
	Copyright string `json:"copyright,omitempty"`
	// ResolvedURL is detection-time evidence carried onto the registry package
	// for matchers (repository resolution reads it). It is raw and never
	// published; the dependency's validated Origin stays on the graph node.
	ResolvedURL string `json:"resolved_url,omitempty"`
	// DetectedOrigins carries the graph node's vetted ADR-0033 origins onto
	// the seeded registry package, so matchers that resolved repositories
	// from the (now identity-stripped) URL-valued purl qualifiers receive
	// the relocated signal. Additive and optional; every element passes the
	// origin codecs' validation. Merge class: union by normalized value.
	DetectedOrigins []DependencyOrigin `json:"detected_origins,omitempty"`

	// Description is the package's own summary of itself, as the source
	// document or registry stated it. SPDX PackageDescription / CycloneDX
	// component description.
	Description string `json:"description,omitempty"`
	// Homepage is the package's project page. SPDX PackageHomePage /
	// CycloneDX an external reference of type website. Held to
	// URLFormReference: a homepage is a citation, so a bare host and a query
	// are legitimate where they would not be for an artifact URL.
	Homepage string `json:"homepage,omitempty"`
	// Supplier is who distributed the package. SPDX PackageSupplier /
	// CycloneDX supplier.
	Supplier *Contact `json:"supplier,omitempty"`
	// Originator is who originally authored the package, which is often not
	// the supplier -- a redistributor supplies what someone else wrote. SPDX
	// PackageOriginator / CycloneDX author or publisher.
	Originator *Contact `json:"originator,omitempty"`

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
	return string(p.Ecosystem) + "\x00" + p.PackageManager.Name() + "\x00" + string(p.Type) + "\x00" + p.Org + "\x00" + p.Name
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

// NormalizeAssertions re-runs the publication gate on every field of p that
// carries untrusted input, in place. Values that cannot be published are
// cleared rather than corrected, following the codecs on DependencyOrigin and
// Contact.
//
// Package has no JSON codec of its own -- it is a large struct decoded by the
// standard rules, and matcher package updates cross the plugin wire as plain
// values -- so there is no unmarshal hook to hang these rules on. This method
// is that hook, and PackageRegistry.Add calls it, which is the one door every
// package goes through on its way into the registry.
func (p *Package) NormalizeAssertions() {
	if p == nil {
		return
	}
	p.Description = NormalizeDescription(p.Description)
	p.Homepage = NormalizeHomepage(p.Homepage)
	p.Supplier = normalizedContact(p.Supplier)
	p.Originator = normalizedContact(p.Originator)
	p.Licenses = MergeLicenses(nil, p.Licenses)
	p.Digests = mergeDigestSet(nil, p.Digests)
	p.DetectedOrigins = MergeOrigins(nil, p.DetectedOrigins)
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
	if len(p.Attestations) > 0 {
		clone.Attestations = make([]PackageAttestation, 0, len(p.Attestations))
		for _, attestation := range p.Attestations {
			clone.Attestations = append(clone.Attestations, attestation.Clone())
		}
	}
	if len(p.DetectedOrigins) > 0 {
		clone.DetectedOrigins = append([]DependencyOrigin(nil), p.DetectedOrigins...)
	}
	clone.Supplier = p.Supplier.Clone()
	clone.Originator = p.Originator.Clone()
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
	// Detected origins union by normalized value: a package seeded from two
	// graph nodes carries every vetted origin either witnessed, so a
	// repository-resolving matcher never loses evidence to seeding order.
	p.DetectedOrigins = MergeOrigins(p.DetectedOrigins, src.DetectedOrigins)
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
	// Each assertion is re-gated as it is taken. Package has no JSON codec of
	// its own -- a matcher's package updates arrive over the plugin wire as
	// plain structs -- so this is where a homepage carrying credentials or a
	// supplier carrying a control character would otherwise enter the registry
	// and be forwarded by PackageRegistry.MarshalJSON unchecked.
	if strings.TrimSpace(p.Description) == "" {
		p.Description = NormalizeDescription(src.Description)
	}
	if p.Homepage == "" {
		p.Homepage = NormalizeHomepage(src.Homepage)
	}
	if p.Supplier == nil {
		p.Supplier = normalizedContact(src.Supplier)
	}
	if p.Originator == nil {
		p.Originator = normalizedContact(src.Originator)
	}
	p.mergeAttestations(src.Attestations)
	// CPEs are a set, not a first-wins scalar. Two matchers can each know a
	// CPE the other does not -- a vendor-specific one from a distro record and
	// a generic one from an advisory -- and keeping only the first seeded
	// slice loses whichever arrived second, which is a matching miss rather
	// than a cosmetic difference.
	p.CPEs = mergeStringSet(p.CPEs, src.CPEs)
	p.mergeDigests(src.Digests)
	// Licenses are a set too, and the declared/concluded distinction makes the
	// old first-wins behavior actively wrong: a source that concluded a
	// license and a source that read the declaration are two claims about one
	// package, and dropping either publishes a partial answer as a complete
	// one.
	p.Licenses = MergeLicenses(p.Licenses, src.Licenses)
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
func SetDetectionLicenses(dep *DependencyNode, licenses []PackageLicense) {
	if dep == nil || len(licenses) == 0 {
		return
	}
	if dep.Metadata == nil {
		dep.Metadata = make(map[string]any, 1)
	}
	dep.Metadata[MetadataKeyDetectionLicenses] = licenses
}

// DetectionLicenses returns license facts stashed on dep at detection time.
func DetectionLicenses(dep *DependencyNode) []PackageLicense {
	if dep == nil || dep.Metadata == nil {
		return nil
	}
	if v, ok := dep.Metadata[MetadataKeyDetectionLicenses].([]PackageLicense); ok {
		return v
	}
	return nil
}

// PackageFromDependencyNode seeds a registry package from a dependency
// node's identity. The node's ID is its canonical package URL, so the
// package is keyed on it directly. The returned package carries no
// enrichment; matchers fill it in. DetectedOrigins projects the node's
// vetted origins onto the package, so matchers that used to read the
// URL-valued purl qualifiers (Scorecard's repository resolution) receive
// the relocated signal.
func PackageFromDependencyNode(dep *DependencyNode) *Package {
	if dep == nil {
		return nil
	}
	purl := dep.NodeID()
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
		Copyright:   dep.Copyright,
		CPEs:        cloneStrings(dep.CPEs),
		// The component-level assertions the detecting or ingesting source
		// made travel with the package, so an ingested document's supplier
		// and description reach the registry rather than stopping at the
		// graph node. Each is re-gated by its own helper: seeding must not be
		// a way around the boundary the wire enforces.
		Description:     NormalizeDescription(dep.Description),
		Homepage:        NormalizeHomepage(dep.Homepage),
		Supplier:        normalizedContact(dep.Supplier),
		Originator:      normalizedContact(dep.Originator),
		Licenses:        MergeLicenses(nil, dep.Licenses),
		Digests:         mergeDigestSet(nil, dep.Digests),
		DetectedOrigins: MergeOrigins(nil, dep.Origins),
	}
}

// normalizedContact re-runs a contact's gate and returns nil when it says
// nothing publishable, so a hand-built value cannot reach a package by way of
// seeding.
func normalizedContact(contact *Contact) *Contact {
	if contact == nil {
		return nil
	}
	normalized, ok := contact.Normalized()
	if !ok {
		return nil
	}
	return &normalized
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
