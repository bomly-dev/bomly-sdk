package sdk

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

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
	// LocatorKindCPE is a CPE 2.2 URI or 2.3 formatted string.
	LocatorKindCPE LocatorKind = "cpe"
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
		normalizeReferenceType(spdxcommon.TypeSecurityCPE23Type): LocatorKindCPE,
		normalizeReferenceType(spdxcommon.TypeSecurityCPE22Type): LocatorKindCPE,
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
	case LocatorKindCPE:
		if !isCPELocator(locator) {
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

// isCPELocator reports whether a value is a CPE in either form the
// specification defines: the 2.3 formatted string, or the 2.2 URI.
//
// # Why this is not delegated
//
// Two CPE libraries were probed before writing this, both already present in
// the CLI's dependency graph. Neither rejects a malformed part component, and
// one is actively worse than no library at all:
//
//   - facebookincubator/nvdtools/wfn accepts "cpe:2.3:x:..." and
//     "cpe:/aardvark" without error, and pads a truncated 2.3 string out to
//     full width rather than refusing it.
//   - umisama/go-cpe silently rewrites the invalid part "x" to "*" and
//     reduces "cpe:/aardvark" to "cpe:/" -- it corrupts the assertion into a
//     valid-looking one, which is the worst possible outcome for a value
//     Bomly publishes.
//
// The part vocabulary is three characters that have not changed since CPE
// 2.3 was published, which is exactly the case the delegation rule leaves to
// hand logic: data the library does not encode. Everything structural about
// the component grammar is still left alone, because nothing in Bomly
// interprets the components -- this only keeps a value that is plainly not a
// CPE out of a field consumers read as one.
func isCPELocator(value string) bool {
	if !isBoundedToken(value) {
		return false
	}
	lower := strings.ToLower(value)
	switch {
	case strings.HasPrefix(lower, "cpe:2.3:"):
		// Escaped colons ("\:") are part of a component, not separators.
		if countUnescapedColons(value) != cpe23FieldCount-1 {
			return false
		}
		return isCPEPart(fieldAt(lower, 2))
	case strings.HasPrefix(lower, "cpe:/"):
		// The 2.2 URI names up to seven components after the prefix; trailing
		// components may be omitted, and the part itself may be empty.
		part := strings.SplitN(lower[len("cpe:/"):], ":", 2)[0]
		return part == "" || isCPEPart(part)
	default:
		return false
	}
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

// fieldAt returns the colon-separated field at index, or "" when absent.
func fieldAt(value string, index int) string {
	fields := strings.Split(value, ":")
	if index >= len(fields) {
		return ""
	}
	return fields[index]
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
func canonicalReferenceType(category ExternalReferenceCategory, referenceType string) string {
	if canonical, ok := canonicalReferenceTypes[normalizeReferenceType(referenceType)]; ok {
		return canonical
	}
	return referenceType
}

// canonicalReferenceTypes indexes every reference type the SPDX
// specification names by its comparison form. The values are
// spdx/tools-golang's constants, so the canonical spelling is the library's.
var canonicalReferenceTypes = buildCanonicalReferenceTypes()

func buildCanonicalReferenceTypes() map[string]string {
	spellings := []string{
		spdxcommon.TypeSecurityCPE23Type, spdxcommon.TypeSecurityCPE22Type,
		spdxcommon.TypeSecurityAdvisory, spdxcommon.TypeSecurityFix,
		spdxcommon.TypeSecurityUrl, spdxcommon.TypeSecuritySwid,
		spdxcommon.TypePackageManagerPURL, spdxcommon.TypePackageManagerMavenCentral,
		spdxcommon.TypePackageManagerNpm, spdxcommon.TypePackageManagerNuGet,
		spdxcommon.TypePackageManagerBower,
		spdxcommon.TypePersistentIdSwh, spdxcommon.TypePersistentIdGitoid,
	}
	index := make(map[string]string, len(spellings))
	for _, spelling := range spellings {
		index[normalizeReferenceType(spelling)] = spelling
	}
	return index
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
func (r ExternalReference) referenceKey() string {
	return string(r.Category) + "\x00" + normalizeReferenceType(r.Type) + "\x00" + r.Locator
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
