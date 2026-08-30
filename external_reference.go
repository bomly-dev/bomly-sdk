package sdk

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	cdx "github.com/CycloneDX/cyclonedx-go"
	spdxcommon "github.com/spdx/tools-golang/spdx/v2/common"

	"github.com/bomly-dev/bomly-sdk/purlkit"
)

// ExternalReferenceCategory is SPDX's referenceCategory axis: the grouping it
// puts an external reference in, alongside the reference type.
//
// It is retained rather than re-derived because SPDX's external reference is a
// triple -- category, type, locator -- and the same type string can appear
// under more than one category in principle. Dropping the category on ingest
// would mean guessing it again on export.
//
// CycloneDX has no equivalent axis. A reference that came from a CycloneDX
// document carries ExternalReferenceCategoryUnknown, which is a fact about the
// source, not a gap to fill in.
type ExternalReferenceCategory string

const (
	// ExternalReferenceCategoryUnknown means the source document has no
	// category axis. Every CycloneDX-sourced reference is this.
	ExternalReferenceCategoryUnknown ExternalReferenceCategory = ""
	// ExternalReferenceCategorySecurity is SPDX's SECURITY.
	ExternalReferenceCategorySecurity ExternalReferenceCategory = "security"
	// ExternalReferenceCategoryPackageManager is SPDX's PACKAGE-MANAGER.
	ExternalReferenceCategoryPackageManager ExternalReferenceCategory = "package-manager"
	// ExternalReferenceCategoryPersistentID is SPDX's PERSISTENT-ID.
	ExternalReferenceCategoryPersistentID ExternalReferenceCategory = "persistent-id"
	// ExternalReferenceCategoryOther is SPDX's OTHER.
	ExternalReferenceCategoryOther ExternalReferenceCategory = "other"
)

// spdxCategoryNames maps each category to its SPDX spelling. A category with
// no entry has no SPDX projection.
// The spellings are spdx/tools-golang's own constants, so a rename upstream is
// a compile error here rather than a document Bomly emits that SPDX rejects.
var spdxCategoryNames = map[ExternalReferenceCategory]string{
	ExternalReferenceCategorySecurity:       spdxcommon.CategorySecurity,
	ExternalReferenceCategoryPackageManager: spdxcommon.CategoryPackageManager,
	ExternalReferenceCategoryPersistentID:   spdxcommon.CategoryPersistentId,
	ExternalReferenceCategoryOther:          spdxcommon.CategoryOther,
}

// ParseExternalReferenceCategory normalizes a category, accepting SPDX's own
// spelling and the canonical token. An empty value is unknown, which is legal
// and is what every CycloneDX-sourced reference carries; anything else
// unrecognized is an error.
func ParseExternalReferenceCategory(value string) (ExternalReferenceCategory, error) {
	if len(value) > maxVocabularyTokenLength {
		return ExternalReferenceCategoryUnknown, fmt.Errorf(
			"external reference category is %d bytes, over the %d byte limit", len(value), maxVocabularyTokenLength)
	}
	normalized := ExternalReferenceCategory(strings.ToLower(strings.TrimSpace(value)))
	switch normalized {
	case ExternalReferenceCategoryUnknown,
		ExternalReferenceCategorySecurity,
		ExternalReferenceCategoryPackageManager,
		ExternalReferenceCategoryPersistentID,
		ExternalReferenceCategoryOther:
		return normalized, nil
	}
	// SPDX writes PACKAGE-MANAGER and PERSISTENT-ID in upper case with the
	// same separator, so the lower-cased form already matches. This catches
	// the underscore spelling some producers emit.
	if underscored := ExternalReferenceCategory(strings.ReplaceAll(string(normalized), "_", "-")); underscored != normalized {
		return ParseExternalReferenceCategory(string(underscored))
	}
	return ExternalReferenceCategoryUnknown, fmt.Errorf("unsupported external reference category %q", value)
}

// SPDXName returns the category's SPDX spelling, or "" when it has none --
// which is the case for a CycloneDX-sourced reference. A caller emitting SPDX
// treats "" as "this reference has no SPDX projection".
func (c ExternalReferenceCategory) SPDXName() string { return spdxCategoryNames[c] }

// String returns the canonical token.
func (c ExternalReferenceCategory) String() string { return string(c) }

// LocatorKind says what shape an external reference's locator has, and so
// which grammar validates it.
//
// It exists because a locator is not always a URL. Both formats carry
// non-URL locators: Bomly itself emits package URLs and CPE values as SPDX
// external references, SPDX's package-manager references carry bare
// coordinates such as "org.apache.tomcat:tomcat:9.0.0.M4", and a persistent
// identifier is a Software Heritage or gitoid string. Validating every
// locator as a URL would discard most of them.
type LocatorKind string

const (
	// LocatorKindURL is a web location, held to URLFormReference.
	LocatorKindURL LocatorKind = "url"
	// LocatorKindPURL is a package URL, held to purlkit.
	LocatorKindPURL LocatorKind = "purl"
	// LocatorKindCPE22 is a CPE 2.2 URI ("cpe:/a:vendor:product").
	LocatorKindCPE22 LocatorKind = "cpe22"
	// LocatorKindCPE23 is a CPE 2.3 formatted string
	// ("cpe:2.3:a:vendor:product:...").
	//
	// The two bindings are separate kinds because the reference type names
	// one of them. Collapsing them into a single "cpe" kind let a cpe23Type
	// reference carry a 2.2 URI and vice versa, so an exporter would publish
	// a reference whose declared type contradicts its own locator.
	LocatorKindCPE23 LocatorKind = "cpe23"
	// LocatorKindIdentifier is the bounded free-form fallback: a token with
	// no whitespace or control characters and no grammar of its own.
	LocatorKindIdentifier LocatorKind = "identifier"
)

// locatorKindByReference names the locator shape for each reference type the
// SPDX specification defines. The type strings are spdx/tools-golang's own
// constants, so a rename upstream breaks the build here; the mapping to a
// shape is Bomly's, because no library states it.
//
// It is keyed on the (category, type) pair rather than the category alone,
// because the category does not determine the shape: SECURITY holds both CPE
// values and advisory URLs, and PACKAGE-MANAGER holds both package URLs and
// bare coordinates.
//
// vocabulary_registry_test.go reads the library's declarations and fails when
// a type it names has no entry here, so a specification addition surfaces as a
// failing build rather than as a locator validated by the wrong grammar.
var locatorKindByReference = map[ExternalReferenceCategory]map[string]LocatorKind{
	ExternalReferenceCategorySecurity: {
		normalizeReferenceType(spdxcommon.TypeSecurityCPE23Type): LocatorKindCPE23,
		normalizeReferenceType(spdxcommon.TypeSecurityCPE22Type): LocatorKindCPE22,
		normalizeReferenceType(spdxcommon.TypeSecurityAdvisory):  LocatorKindURL,
		normalizeReferenceType(spdxcommon.TypeSecurityFix):       LocatorKindURL,
		normalizeReferenceType(spdxcommon.TypeSecurityUrl):       LocatorKindURL,
		normalizeReferenceType(spdxcommon.TypeSecuritySwid):      LocatorKindIdentifier,
	},
	ExternalReferenceCategoryPackageManager: {
		normalizeReferenceType(spdxcommon.TypePackageManagerPURL): LocatorKindPURL,
		// These carry the package manager's own coordinate form, not a URL:
		// "org.apache.tomcat:tomcat:9.0.0.M4" for maven-central.
		normalizeReferenceType(spdxcommon.TypePackageManagerMavenCentral): LocatorKindIdentifier,
		normalizeReferenceType(spdxcommon.TypePackageManagerNpm):          LocatorKindIdentifier,
		normalizeReferenceType(spdxcommon.TypePackageManagerNuGet):        LocatorKindIdentifier,
		normalizeReferenceType(spdxcommon.TypePackageManagerBower):        LocatorKindIdentifier,
	},
	ExternalReferenceCategoryPersistentID: {
		normalizeReferenceType(spdxcommon.TypePersistentIdSwh):    LocatorKindIdentifier,
		normalizeReferenceType(spdxcommon.TypePersistentIdGitoid): LocatorKindIdentifier,
	},
}

// LocatorKindFor derives the locator shape from a reference's category and
// type. The pair is the input, never the category alone: an SPDX-only axis
// cannot decide the shape of a reference that arrived without one.
//
// A reference with no category came from CycloneDX, whose schema types the
// field as an IRI reference, so its locator is a URL. A known category with an
// unrecognized type -- SPDX's OTHER, and any type the specification adds after
// this table was written -- takes the bounded identifier form, which accepts
// the most and asserts the least.
func LocatorKindFor(category ExternalReferenceCategory, referenceType string) LocatorKind {
	if kinds, ok := locatorKindByReference[category]; ok {
		if kind, ok := kinds[normalizeReferenceType(referenceType)]; ok {
			return kind
		}
		return LocatorKindIdentifier
	}
	if category == ExternalReferenceCategoryUnknown {
		return LocatorKindURL
	}
	return LocatorKindIdentifier
}

// normalizeReferenceType reduces a reference type to its comparison form.
// SPDX writes "cpe23Type" and CycloneDX writes lower-case tokens, so the
// vocabulary is compared case-insensitively.
func normalizeReferenceType(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// maxReferenceTypeLength bounds a reference type. The longest name in either
// specification is well under this; the allowance leaves room for a vocabulary
// that grows without admitting a value that is really a payload.
const maxReferenceTypeLength = 64

// maxLocatorLength bounds a locator. It matches the published-URL limit,
// since a URL is the longest locator form.
const maxLocatorLength = maxPublishedURLLength

// maxReferenceCommentLength bounds a reference comment.
const maxReferenceCommentLength = 4096

// ExternalReference is one external reference a source document attached to a
// component: an advisory, a repository, a package-manager coordinate, a CPE.
//
// # Gate and merge class
//
// Every field is gated by ExternalReference.Normalized, applied on both wire
// directions. A reference whose locator cannot be published is dropped
// entirely rather than published without it, since a reference with no locator
// points at nothing.
//
// References are a set. Their identity is the (category, type, locator)
// triple, so the same locator recorded under two types stays two references --
// they say different things about the component. Hashes union within a
// matching reference, and the comment fills a gap.
type ExternalReference struct {
	// Category is SPDX's referenceCategory. Empty for a CycloneDX-sourced
	// reference, which has no such axis.
	Category ExternalReferenceCategory `json:"category,omitempty"`
	// Type is the reference type: SPDX's referenceType or CycloneDX's type.
	// The vocabulary is open -- both specifications add types, and a type
	// this build does not know still round-trips -- so it is bounded and
	// checked for shape rather than matched against a closed list.
	Type string `json:"type,omitempty"`
	// Locator is what the reference points at. Its shape is decided by
	// LocatorKindFor, not by inspecting the value: a locator that fails its
	// declared grammar is a rejected reference, not one to reclassify.
	Locator string `json:"locator,omitempty"`
	// Comment is the source document's note about this reference. SPDX has a
	// comment field; CycloneDX 1.6 has one too.
	Comment string `json:"comment,omitempty"`
	// Hashes are the reference's own integrity claims. CycloneDX carries
	// these natively; SPDX 2.3 has no slot for them, so a caller emitting
	// SPDX has nowhere to put them and omits them.
	//
	// Gate: Digest.Normalized, through mergeDigestSet. Merge class: set,
	// unioned by the digest's own identity.
	Hashes []Digest `json:"hashes,omitempty"`
}

// LocatorKind returns the shape this reference's locator is held to.
func (r ExternalReference) LocatorKind() LocatorKind {
	return LocatorKindFor(r.Category, r.Type)
}

// Normalized returns the reference with every field re-checked, or false when
// it says nothing publishable. It is the gate for a reference that arrived
// from a plugin, an ingested document, or a hand-built value.
func (r ExternalReference) Normalized() (ExternalReference, bool) {
	normalized := ExternalReference{
		Type:    strings.TrimSpace(r.Type),
		Comment: NormalizeDescription(r.Comment),
		Hashes:  mergeDigestSet(nil, r.Hashes),
	}
	// An unrecognized category is refused, not cleared. Empty carries meaning
	// here -- it says the reference came from a document with no category
	// axis, which is CycloneDX -- so silently emptying a misspelled "SECURTY"
	// would rewrite the source's assertion, change the merge identity, and
	// drop the reference's SPDX projection.
	category, err := ParseExternalReferenceCategory(string(r.Category))
	if err != nil {
		return ExternalReference{}, false
	}
	normalized.Category = category
	if len(normalized.Comment) > maxReferenceCommentLength {
		normalized.Comment = ""
	}
	// A malformed type takes the whole reference with it. Both formats
	// require one, it is part of the merge identity, and it decides which
	// grammar the locator is held to -- so clearing it would validate the
	// locator under the fallback kind and then publish a typeless reference
	// that neither format can express.
	if normalized.Type == "" || len(normalized.Type) > maxReferenceTypeLength || !isBoundedToken(normalized.Type) {
		return ExternalReference{}, false
	}
	// A recognized type is stored in the specification's own spelling. The
	// vocabulary compares case-insensitively, so "CPE23TYPE" and "cpe23Type"
	// are one reference -- without canonicalizing, which spelling reached the
	// document would depend on which witness arrived first.
	normalized.Type = canonicalReferenceType(normalized.Category, normalized.Type)
	locator, ok := normalizeLocator(strings.TrimSpace(r.Locator), LocatorKindFor(normalized.Category, normalized.Type))
	if !ok {
		// A reference with no usable locator points at nothing. There is no
		// partial form worth publishing.
		return ExternalReference{}, false
	}
	normalized.Locator = locator
	return normalized, true
}

// normalizeLocator applies the grammar the kind names.
//
// The result is bounded as well as the input. Canonical rendering can make a
// value longer than it arrived -- a package URL re-encodes characters its
// grammar requires escaped -- so a locator just under the limit can normalize
// to one just over it, which would be accepted on write and rejected on read.
func normalizeLocator(locator string, kind LocatorKind) (string, bool) {
	normalized, ok := normalizeLocatorByKind(locator, kind)
	if !ok || len(normalized) > maxLocatorLength {
		return "", false
	}
	return normalized, true
}

func normalizeLocatorByKind(locator string, kind LocatorKind) (string, bool) {
	if locator == "" || len(locator) > maxLocatorLength {
		return "", false
	}
	switch kind {
	case LocatorKindURL:
		return NormalizeURL(locator, URLFormReference)
	case LocatorKindPURL:
		// purlkit is the single home for package URL semantics (ADR-0038),
		// so the locator is held to the same standard a dependency identity
		// is -- including the per-type profile rules.
		if err := purlkit.ValidateString(locator); err != nil {
			return "", false
		}
		parsed, err := purlkit.Parse(locator)
		if err != nil {
			return "", false
		}
		return parsed.String(), true
	case LocatorKindCPE23:
		if !isCPE23Locator(locator) {
			return "", false
		}
		return locator, true
	case LocatorKindCPE22:
		if !isCPE22Locator(locator) {
			return "", false
		}
		return locator, true
	default:
		if !isBoundedToken(locator) {
			return "", false
		}
		return locator, true
	}
}

// isBoundedToken reports whether a value is a single token safe to write into
// a document field: valid UTF-8, with no whitespace and no control characters.
//
// The checks are Unicode-aware. An em space is as much whitespace as a space,
// and invalid UTF-8 is replaced by encoding/json with U+FFFD, which would make
// a value serialize differently than it validated.
func isBoundedToken(value string) bool {
	if value == "" {
		return false
	}
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// cpe23FieldCount is the number of colon-separated fields in a CPE 2.3
// formatted string, counting the "cpe" and "2.3" prefix fields.
const cpe23FieldCount = 13

// cpe22ComponentCount is the number of components a CPE 2.2 URI names after
// the "cpe:/" prefix: part, vendor, product, version, update, edition,
// language.
const cpe22ComponentCount = 7

// The CPE validators below are deliberately not delegated. Two CPE libraries
// already in the CLI's dependency graph were probed against the exact inputs
// under review, and neither is usable here:
//
//   - facebookincubator/nvdtools/wfn correctly rejects a mismatched binding,
//     but accepts "cpe:2.3:x:..." and "cpe:/aardvark" (the part component is
//     not validated) and silently TRUNCATES an overlong 2.2 URI:
//     "cpe:/a:v:p:1:u:e:l:extra" parses without error and re-binds as
//     "cpe:/a:v:p:1:u:e:l", dropping a component.
//   - umisama/go-cpe rewrites the invalid part "x" to "*" and reduces
//     "cpe:/aardvark" to "cpe:/".
//
// Both silently repair malformed input into valid-looking values, which is
// the worst outcome for something Bomly publishes as an assertion. What is
// checked here is the part vocabulary and the component count -- fixed since
// CPE 2.3 was published, and small enough to state -- while the component
// grammar itself is left alone, because nothing in Bomly interprets the
// components. This only keeps a value that is plainly not a CPE out of a
// field consumers read as one.

// isCPE23Locator reports whether a value is a CPE 2.3 formatted string.
func isCPE23Locator(value string) bool {
	if !isBoundedToken(value) {
		return false
	}
	lower := strings.ToLower(value)
	if !strings.HasPrefix(lower, "cpe:2.3:") {
		return false
	}
	// Escaped colons ("\:") are part of a component, not separators.
	if countUnescapedColons(value) != cpe23FieldCount-1 {
		return false
	}
	if !isCPEPart(fieldAt(lower, 2)) {
		return false
	}
	// Every component carries a value: a literal, or the logical ANY ("*") or
	// NA ("-"). An empty one is not "unspecified" in this binding -- the
	// binding has spellings for that -- so "cpe:2.3:a::::::::::" is malformed
	// however well it counts.
	for _, component := range splitUnescaped(value)[2:] {
		if component == "" {
			return false
		}
	}
	return true
}

// isCPE22Locator reports whether a value is a CPE 2.2 URI.
func isCPE22Locator(value string) bool {
	if !isBoundedToken(value) {
		return false
	}
	lower := strings.ToLower(value)
	if !strings.HasPrefix(lower, "cpe:/") {
		return false
	}
	// The binding names at most seven components, and trailing ones may be
	// omitted. An eighth is not a CPE -- and must not be quietly dropped to
	// make it one, which is what the library does.
	components := strings.Split(lower[len("cpe:/"):], ":")
	if len(components) > cpe22ComponentCount {
		return false
	}
	return components[0] == "" || isCPEPart(components[0])
}

// isCPEPart reports whether a value is a CPE part component: one of the three
// defined values, or a logical ANY or NA.
func isCPEPart(value string) bool {
	switch value {
	case "a", "o", "h", "*", "-":
		return true
	default:
		return false
	}
}

// fieldAt returns the field at index, or "" when absent.
func fieldAt(value string, index int) string {
	fields := splitUnescaped(value)
	if index >= len(fields) {
		return ""
	}
	return fields[index]
}

// splitUnescaped splits on the colons that act as field separators, leaving
// escaped ones ("\:") inside the component they belong to.
func splitUnescaped(value string) []string {
	fields := []string{}
	current := strings.Builder{}
	for i := 0; i < len(value); i++ {
		if value[i] == ':' && (i == 0 || value[i-1] != '\\') {
			fields = append(fields, current.String())
			current.Reset()
			continue
		}
		current.WriteByte(value[i])
	}
	return append(fields, current.String())
}

// countUnescapedColons counts the colons that act as field separators.
func countUnescapedColons(value string) int {
	count := 0
	for i := 0; i < len(value); i++ {
		if value[i] != ':' {
			continue
		}
		if i > 0 && value[i-1] == '\\' {
			continue
		}
		count++
	}
	return count
}

// canonicalReferenceType returns the specification's own spelling of a type
// the vocabulary recognizes, and the value as given otherwise -- the type
// vocabulary is open, so an unrecognized type is carried, not corrected.
//
// Which specification is decided by the category, because that is what says
// where the reference came from: a categorised reference is SPDX's, and a
// category-less one is CycloneDX's. Looking in one registry only meant a
// CycloneDX "WEBSITE" was carried as typed, so it merged with "website" --
// the comparison is case-insensitive -- but published whichever spelling
// folded first.
func canonicalReferenceType(category ExternalReferenceCategory, referenceType string) string {
	registry := canonicalCycloneDXReferenceTypes
	if category != ExternalReferenceCategoryUnknown {
		registry = canonicalSPDXReferenceTypes
	}
	if canonical, ok := registry[normalizeReferenceType(referenceType)]; ok {
		return canonical
	}
	return referenceType
}

// canonicalSPDXReferenceTypes and canonicalCycloneDXReferenceTypes index each
// specification's reference types by their comparison form. The values are
// the libraries' own constants, so the canonical spelling is theirs and a
// rename upstream is a compile error here.
//
// vocabulary_registry_test.go diffs both against the libraries' declarations,
// which is what catches a type added upstream -- a constant reference cannot.
var (
	canonicalSPDXReferenceTypes = indexReferenceTypes(
		spdxcommon.TypeSecurityCPE23Type, spdxcommon.TypeSecurityCPE22Type,
		spdxcommon.TypeSecurityAdvisory, spdxcommon.TypeSecurityFix,
		spdxcommon.TypeSecurityUrl, spdxcommon.TypeSecuritySwid,
		spdxcommon.TypePackageManagerPURL, spdxcommon.TypePackageManagerMavenCentral,
		spdxcommon.TypePackageManagerNpm, spdxcommon.TypePackageManagerNuGet,
		spdxcommon.TypePackageManagerBower,
		spdxcommon.TypePersistentIdSwh, spdxcommon.TypePersistentIdGitoid,
	)
	canonicalCycloneDXReferenceTypes = indexCycloneDXReferenceTypes()
)

func indexReferenceTypes(spellings ...string) map[string]string {
	index := make(map[string]string, len(spellings))
	for _, spelling := range spellings {
		index[normalizeReferenceType(spelling)] = spelling
	}
	return index
}

func indexCycloneDXReferenceTypes() map[string]string {
	types := []cdx.ExternalReferenceType{
		cdx.ERTypeAdversaryModel,
		cdx.ERTypeAdvisories,
		cdx.ERTypeAttestation,
		cdx.ERTypeBOM,
		cdx.ERTypeBuildMeta,
		cdx.ERTypeBuildSystem,
		cdx.ERTypeCertificationReport,
		cdx.ERTypeChat,
		cdx.ERTypeConfiguration,
		cdx.ERTypeCodifiedInfrastructure,
		cdx.ERTypeComponentAnalysisReport,
		cdx.ERTypeDistribution,
		cdx.ERTypeDistributionIntake,
		cdx.ERTypeDocumentation,
		cdx.ERTypeDynamicAnalysisReport,
		cdx.ERTypeDigitalSignature,
		cdx.ERTypeElectronicSignature,
		cdx.ERTypeEvidence,
		cdx.ERTypeExploitabilityStatement,
		cdx.ERTypeFormulation,
		cdx.ERTypeIssueTracker,
		cdx.ERTypeLicense,
		cdx.ERTypeLog,
		cdx.ERTypeMailingList,
		cdx.ERTypeMaturityReport,
		cdx.ERTypeModelCard,
		cdx.ERTypeOther,
		cdx.ERTypePentestReport,
		cdx.ERTypePOAM,
		cdx.ERTypeQualityMetrics,
		cdx.ERTypeReleaseNotes,
		cdx.ERTypeRiskAssessment,
		cdx.ERTypeRFC9116,
		cdx.ERTypeRuntimeAnalysisReport,
		cdx.ERTypeSecurityContact,
		cdx.ERTypeSocial,
		cdx.ERTypeSourceDistribution,
		cdx.ERTypeStaticAnalysisReport,
		cdx.ERTypeSupport,
		cdx.ERTypeThreatModel,
		cdx.ERTypeVCS,
		cdx.ERTypeVulnerabilityAssertion,
		cdx.ERTypeWebsite,
		cdx.ERTypePatent,
		cdx.ERTypePatentFamily,
		cdx.ERTypePatentAssertion,
		cdx.ERTypeCitation,
	}
	spellings := make([]string, 0, len(types))
	for _, referenceType := range types {
		spellings = append(spellings, string(referenceType))
	}
	return indexReferenceTypes(spellings...)
}

// reconcileComments picks one comment for a reference two witnesses both
// described. A gap is filled, and two different notes resolve to the
// lexicographically smaller one.
//
// The tie-break is arbitrary but it has to exist: "first non-empty wins"
// makes the exported document depend on the order consolidation happened to
// fold witnesses in, which is the same nondeterminism the reference sort
// removes and which a sort cannot fix inside a single record.
func reconcileComments(existing, incoming string) string {
	switch {
	case incoming == "":
		return existing
	case existing == "":
		return incoming
	case incoming < existing:
		return incoming
	default:
		return existing
	}
}

// referenceKey is the merge identity of an external reference: the triple the
// formats treat as one assertion.
// The type is compared as stored, not case-folded. Normalized has already
// rewritten a recognized type to its specification's spelling, so those still
// collapse; an unrecognized one keeps the spelling its source used, and
// folding case here would merge "Acme-ID" with "acme-id" and then publish
// whichever witness folded first. The open vocabulary has no case rule to
// apply, so two spellings stay two assertions.
func (r ExternalReference) referenceKey() string {
	return string(r.Category) + "\x00" + r.Type + "\x00" + r.Locator
}

// MergeExternalReferences unions reference sets, keeping the first record of
// each distinct triple. A later record with the same triple contributes its
// hashes and fills a missing comment: it is the same assertion, seen twice.
//
// Both sides are re-gated, and no early return when one is empty -- an
// existing slice may hold references that never passed the gate, and returning
// it untouched would leave them visible to in-process consumers.
func MergeExternalReferences(existing, additions []ExternalReference) []ExternalReference {
	if len(existing) == 0 && len(additions) == 0 {
		return nil
	}
	merged := make([]ExternalReference, 0, len(existing)+len(additions))
	seen := make(map[string]int, len(existing)+len(additions))
	for _, group := range [][]ExternalReference{existing, additions} {
		for _, reference := range group {
			normalized, ok := reference.Normalized()
			if !ok {
				continue
			}
			key := normalized.referenceKey()
			if at, found := seen[key]; found {
				merged[at].Hashes = mergeDigestSet(merged[at].Hashes, normalized.Hashes)
				merged[at].Comment = reconcileComments(merged[at].Comment, normalized.Comment)
				continue
			}
			seen[key] = len(merged)
			merged = append(merged, normalized)
		}
	}
	if len(merged) == 0 {
		return nil
	}
	// Sorted so a set built from the same references in different orders
	// publishes the same document. Consolidation folds witnesses in whatever
	// order they arrive, and an unstable order would make every export differ.
	sort.Slice(merged, func(i, j int) bool { return merged[i].referenceKey() < merged[j].referenceKey() })
	return merged
}

// externalReferenceWire carries ExternalReference's fields without its
// methods, so the JSON hooks below can encode and decode without recursing.
type externalReferenceWire ExternalReference

// UnmarshalJSON applies the reference rule as a value arrives, so a locator
// that would be rejected on read cannot be stored, forwarded, or written back
// out. A reference that says nothing publishable decodes to the zero value,
// following DependencyOrigin.
func (r *ExternalReference) UnmarshalJSON(data []byte) error {
	var wire externalReferenceWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	normalized, ok := ExternalReference(wire).Normalized()
	if !ok {
		*r = ExternalReference{}
		return nil
	}
	*r = normalized
	return nil
}

// MarshalJSON applies the same rule on the way out.
func (r ExternalReference) MarshalJSON() ([]byte, error) {
	normalized, ok := r.Normalized()
	if !ok {
		return json.Marshal(externalReferenceWire{})
	}
	return json.Marshal(externalReferenceWire(normalized))
}
