package sdk

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

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

// maxVocabularyTokenLength bounds a token drawn from one of the model's
// closed vocabularies. The longest is "noassertion" at eleven characters; the
// allowance leaves room for whitespace padding and a spelling variant without
// admitting a value that is really a payload.
const maxVocabularyTokenLength = 64

// maxLicenseSourceLength bounds a license source. It is a component name, not
// a vocabulary token, so it is the component-name bound by reference: every
// name that validates as a component survives here, and a bound that rejected
// a valid one would erase provenance rather than protect anything. It used to
// be the contact-name allowance instead, which happened to be the same number
// while descriptor validation put no length on a name at all -- so a 257-byte
// matcher was a valid component whose source this erased (#32). Tying the two
// by name rather than by value is what keeps them from drifting again.
//
// The bound itself stays: this value arrives on an untrusted wire and is
// written into published documents, and an unbounded field there costs more
// than any name a component would carry. It is a resource limit and stays a
// dumb one.
const maxLicenseSourceLength = maxComponentNameLength

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
	// Bounded before any work, as the other closed vocabularies are. The
	// longest valid value is nine characters, so a longer one cannot match --
	// lowercasing it and formatting it into an error the caller discards
	// would spend memory proportional to whatever was sent.
	if len(value) > maxVocabularyTokenLength {
		return "", fmt.Errorf("license type is %d bytes, over the %d byte limit", len(value), maxVocabularyTokenLength)
	}
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

	// Adding these cost PackageLocation its comparability: a struct holding a
	// slice cannot be compared with == or used as a map key. That is a real
	// break, taken deliberately -- gorelease names it and this PR carries the
	// api:break-approved label. Neither this module nor the CLI compared
	// locations or keyed a map by one, and encoding the set as a string to
	// keep comparability would reintroduce the untyped stash that phase 1.4
	// exists to remove. Compare RealPath and AccessPath, or key by them.

	// ModuleRoot is the module whose resolution produced this site: a
	// workspace member's directory, a Go main module, a Maven reactor
	// project. Empty when the producer did not attribute it.
	//
	// It is what makes the fields below answerable. "Is this package a direct
	// runtime dependency?" has no single answer for a workspace -- it can be
	// direct-in-development in one module and transitive-at-runtime in
	// another -- and a question with two answers can only be asked per module
	// root.
	ModuleRoot string `json:"module_root,omitempty"`
	// Scopes are the scopes this particular site was reached under, as
	// opposed to the union across every site, which is what the node carries.
	Scopes []Scope `json:"scopes,omitempty"`
	// Relationship is whether this site was declared directly by its module
	// root or reached through another dependency. Same reasoning as Scopes:
	// the node-level value is a union and cannot distinguish the sites.
	Relationship DependencyRelationship `json:"relationship,omitempty"`
}

// PackageLicense captures normalized license details for a package.
type PackageLicense struct {
	// Value is the license as the source stated it, unmodified.
	Value string `json:"value,omitempty"`
	// SPDXExpression is the validated SPDX expression form, when the value
	// has one. For a license that is not on the SPDX list, this is a minted
	// LicenseRef-* identifier whose text is carried in ExtractedText.
	SPDXExpression string `json:"spdx_expression,omitempty"`
	// Type is what kind of claim this is: declared by the package, or
	// concluded by an analysis. See LicenseType.
	Type LicenseType `json:"type,omitempty"`
	// Source names the component that supplied the claim -- a matcher name
	// such as "external-depsdev". It answers "who says so", which Type does
	// not: Type is a closed two-member vocabulary about the kind of claim,
	// and the two questions are independent. A deps.dev license is declared
	// *and* sourced from deps.dev.
	//
	// They were briefly the same field, which is how this one came to exist.
	// matcherkit.NormalizeLicenseSet wrote its matcher name into Type, so
	// once Type became a closed vocabulary the gate dropped the value --
	// silently emptying the "licenses[].source" field the CLI documents and
	// publishes. Two independent facts sharing one field is what made that
	// possible.
	//
	// Gate: PackageLicense.Normalized -- held to the component-name rule,
	// not a token rule. A component descriptor requires only a non-blank
	// name, so "My Matcher" and a name over 64 bytes are both valid
	// components; gating this as a single short token would silently erase
	// the source of a legitimately named matcher. What is enforced is what
	// publication actually needs: valid UTF-8, no control characters, and a
	// bound.
	// Merge class: scalar, fill-gaps *within* a claim. Source is deliberately
	// not part of the merge identity -- two matchers reporting one license
	// stay one claim -- so the witness that carries a source supplies it to
	// the one that does not, whichever arrived first.
	Source string `json:"source,omitempty"`
	// Name is the human-readable license name for a LicenseRef-* identifier.
	// SPDX's hasExtractedLicensingInfos carries one, and a reader given only
	// "LicenseRef-bomly-3f2a..." has nothing to go on.
	//
	// Gate: PackageLicense.Normalized (trimmed; cleared with the expression
	// when a reference cannot be published). Merge class: scalar, fill-gaps
	// *within* a claim -- Name is deliberately not part of the merge
	// identity, so two records naming one license stay one claim and the
	// witness that carries a name supplies it to the one that does not.
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
	//
	// Gate: PackageLicense.Normalized -- bounded, and blank text is cleared
	// (it would otherwise mint the reference empty text mints, so every
	// package with a blank license file would share one citation).
	//
	// Merge class: set member, and part of the merge identity -- by what the
	// text mints rather than by its bytes, since whitespace-only differences
	// name one license. Two claims whose texts genuinely differ are both
	// kept, and if they arrived under one reference the later is re-minted so
	// the set never leaves one identifier naming two licenses.
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
	// A source is a component name written into published output, so its
	// domain is the component-name domain descriptor validation enforces:
	// bounded, valid UTF-8, no control characters (they would corrupt SPDX's
	// line-oriented tag form). Re-checked here because a source arrives on
	// the wire, not through a descriptor. Whitespace is legal in a name and
	// is kept.
	if source := strings.TrimSpace(l.Source); source != "" &&
		len(source) <= maxLicenseSourceLength &&
		utf8.ValidString(source) && !containsControlChar(source) {
		normalized.Source = source
	}
	// Whitespace-only text is not text. It would otherwise mint the reference
	// that empty text mints and publish a citation whose licensing entry says
	// nothing -- a document that does not validate and, worse, one where
	// every package with blank text shares one reference.
	if len(normalized.ExtractedText) > maxExtractedLicenseTextLength || strings.TrimSpace(normalized.ExtractedText) == "" {
		normalized.ExtractedText = ""
	}
	// The test is "is this expression a single well-formed reference", not
	// "does it start with the prefix". A compound whose first operand happens
	// to be a reference -- "LicenseRef-Acme OR MIT" -- is an expression, and
	// treating it as a bare reference re-minted the whole thing and dropped
	// the "OR MIT" operand, while the same claim written the other way round
	// survived intact. Operand order must not decide whether a license is
	// kept. Everything that is not a bare reference, malformed references
	// included, goes to the expression path below.
	if spdxkit.ValidLicenseRef(normalized.SPDXExpression) {
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
	// Declined before any spdxkit call. Each of those bounds the value itself
	// before it parses, so nothing over-limit reaches a parser either way;
	// this simply stops an oversized value from being scanned three times,
	// and it borrows spdxkit's limit rather than keeping a second copy of it.
	if !spdxkit.WithinBounds(expression) {
		return ""
	}
	if strings.Contains(expression, spdxkit.LicenseRefPrefix) {
		if strings.TrimSpace(extractedText) == "" {
			return ""
		}
		refs := spdxkit.LicenseRefsIn(expression)
		// One record carries one ExtractedText, so an expression naming two
		// references cannot supply the text for both, and at least one
		// citation in it would dangle. Refused for the same reason a bare
		// reference without text is.
		if len(refs) > 1 {
			return ""
		}
		// Every reference published inside an expression is held to the same
		// standard as one published on its own. The expression parser does
		// not bound identifier length, so without this a reference far too
		// long to be an identifier -- a payload wearing the prefix -- would
		// be refused when it stood alone and accepted when it appeared in an
		// expression. The fuzzer found exactly that divergence.
		for _, ref := range refs {
			if !spdxkit.ValidLicenseRef(ref) {
				return ""
			}
			// A reference under Bomly's prefix is derived from its text
			// wherever it appears, not only when it is the whole expression.
			// Validating it and moving on would let a stale or spoofed one
			// ride inside a compound and name a license its text does not
			// mint -- the invariant the bare-reference branch enforces,
			// silently suspended by an "OR".
			if strings.HasPrefix(ref, spdxkit.BomlyLicenseRefPrefix) {
				minted := spdxkit.MintLicenseRef(extractedText).RefID
				if ref != minted {
					expression = spdxkit.ReplaceLicenseRef(expression, ref, minted)
				}
			}
		}
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
	// No early return when additions is empty. The existing slice may hold
	// claims that were never gated -- a hand-built package, or one mutated
	// through Ensure -- and returning it untouched left them visible to
	// in-process consumers such as Get, All, and LicenseValues, which would
	// report a license the wire would refuse to publish. mergeDigestSet
	// processes both sides for the same reason.
	if len(existing) == 0 && len(additions) == 0 {
		return nil
	}
	merged := make([]PackageLicense, 0, mergeCapacity(len(existing), len(additions)))
	seen := make(map[string]int, mergeCapacity(len(existing), len(additions)))
	// textByRef records which text each surviving reference names, so a second
	// claim reusing that reference for different terms can be spotted.
	textByRef := make(map[string]string, mergeCapacity(len(existing), len(additions)))
	for _, group := range [][]PackageLicense{existing, additions} {
		for _, license := range group {
			normalized, ok := license.Normalized()
			if !ok {
				continue
			}
			normalized = resolveLicenseRefCollision(normalized, textByRef)
			key := normalized.licenseKey()
			if at, found := seen[key]; found {
				// The same claim seen twice, but one witness may carry the
				// human-readable name and the other may not. Dropping the
				// later record wholesale threw that name away, which matters
				// most for a LicenseRef-* claim: without it a reader has only
				// "LicenseRef-bomly-3f2a..." to go on. Name is not part of
				// the identity -- two records naming one license are still
				// one claim -- so it fills the gap instead.
				if merged[at].Name == "" {
					merged[at].Name = normalized.Name
				}
				// Source is a fill-gaps scalar within a claim, the same class
				// as Name and for the same reason: it is not part of the
				// merge identity, so an unsourced copy of a claim and a
				// matcher-sourced copy are one claim, and whichever arrived
				// first would otherwise decide whether the provenance
				// survives. Making it part of the identity instead would
				// split one license into two entries per matcher that saw it.
				if merged[at].Source == "" {
					merged[at].Source = normalized.Source
				}
				continue
			}
			seen[key] = len(merged)
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
// The reference may be the whole expression or embedded in a compound one
// ("MIT OR LicenseRef-Custom"), so the references are enumerated by the parser
// rather than by testing the expression's prefix. A compound naming more than
// one reference is dropped instead: the record carries a single ExtractedText,
// which cannot be the text of two different references, so at least one
// citation in it would dangle -- the same rule the bare-reference case applies.
func resolveLicenseRefCollision(license PackageLicense, textByRef map[string]string) PackageLicense {
	text := strings.TrimSpace(license.ExtractedText)
	if text == "" {
		return license
	}
	refs := spdxkit.LicenseRefsIn(license.SPDXExpression)
	if len(refs) != 1 {
		// None to collide, or more than one -- which Normalized has already
		// refused, since one ExtractedText cannot be the text of two
		// references.
		return license
	}
	ref := refs[0]
	// Texts are compared by what they mint, not by their bytes. MintLicenseRef
	// collapses whitespace before hashing, so two texts differing only in
	// spacing name the same license -- comparing bytes would send them down
	// the re-mint path, where the mint equals the reference already in hand
	// and the assignment changes nothing, leaving one reference naming two
	// texts: precisely the ambiguity this function exists to prevent.
	minted := spdxkit.MintLicenseRef(license.ExtractedText).RefID
	prior, seen := textByRef[ref]
	switch {
	case !seen:
		textByRef[ref] = text
	case spdxkit.MintLicenseRef(prior).RefID == minted:
		// The same license written differently. Adopt the text already
		// recorded for this reference so the two records agree byte for byte
		// rather than differing in whitespace under one identifier.
		license.ExtractedText = prior
	default:
		license.SPDXExpression = spdxkit.ReplaceLicenseRef(license.SPDXExpression, ref, minted)
		textByRef[minted] = text
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
	//
	// Gate: NormalizeDescription -- trimmed and bounded, control characters
	// dropped, an over-long value cleared rather than truncated.
	// Merge class: scalar, fill-gaps. The first publishable witness wins and
	// a later one contributes only what is missing.
	Description string `json:"description,omitempty"`
	// Homepage is the package's project page. SPDX PackageHomePage /
	// CycloneDX an external reference of type website.
	//
	// Gate: NormalizeHomepage -- URLFormReference, so a bare host and a query
	// are legitimate where they would not be for an artifact URL, while
	// credentials, local paths, and non-http schemes are cleared.
	// Merge class: scalar, fill-gaps.
	Homepage string `json:"homepage,omitempty"`
	// Supplier is who distributed the package. SPDX PackageSupplier /
	// CycloneDX supplier.
	//
	// Gate: Contact.Normalized -- an unpublishable contact becomes nil, and
	// no email address is retained (see Contact).
	// Merge class: scalar, fill-gaps.
	Supplier *Contact `json:"supplier,omitempty"`
	// Originator is who originally authored the package, which is often not
	// the supplier -- a redistributor supplies what someone else wrote. SPDX
	// PackageOriginator / CycloneDX author or publisher.
	//
	// Gate and merge class: as Supplier.
	Originator *Contact `json:"originator,omitempty"`
	// ExternalReferences are the references a source document attached to
	// this component: advisories, repositories, package-manager coordinates,
	// CPE values. SPDX externalRefs / CycloneDX externalReferences.
	//
	// Gate: ExternalReference.Normalized. Merge class: set, unioned by the
	// (category, type, locator) triple through MergeExternalReferences.
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`

	// CPEs, Digests, and Licenses are set-valued: every witness's claims
	// survive a merge, because two sources can each know something the other
	// does not. Gates: Digest.Normalized and PackageLicense.Normalized drop
	// what cannot be published; MergeLicenses additionally keeps two sources
	// that reuse one license reference for different terms apart.
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
//
// Deprecated: use SetDetectionLicenses and DetectionLicenses, which write and
// read the typed field. The stash predates that field and is still read on
// ingest so a payload written by an older producer is not dropped, but nothing
// should write it.
//
// The stash is why this deprecation exists rather than a rename. A value here
// is invisible to every gate -- not normalized, not validated, not merged by a
// declared rule, not projected to either document format -- so a license that
// lived only in this key was dropped by any consumer that had not learned to
// look for it. That is the failure the typed field removes, and keeping both
// spellings writable would leave one of them able to reintroduce it.
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

// packageWire carries Package's fields without its methods, so the JSON hooks
// below can encode and decode without recursing.
type packageWire Package

// UnmarshalJSON applies the package rule as a value arrives, and MarshalJSON
// applies it again on the way out.
//
// The codec lives on the type because the registry is not the only path a
// package takes. A matcher or analyzer returns PackageUpdates on its result,
// which the plugin transport serializes directly -- never through
// PackageRegistry -- so a gate that lived only at the registry let a
// credential-bearing homepage cross the wire, and let contacts and digests the
// model had already rejected encode as empty "{}" objects.
func (p *Package) UnmarshalJSON(data []byte) error {
	var wire packageWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	decoded := Package(wire)
	decoded.NormalizeAssertions()
	*p = decoded
	return nil
}

// MarshalJSON re-gates on the way out. The receiver is a value, so
// normalization applies to this copy and never rewrites the record its holder
// still owns.
func (p Package) MarshalJSON() ([]byte, error) {
	p.NormalizeAssertions()
	return json.Marshal(packageWire(p))
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
	p.ExternalReferences = MergeExternalReferences(nil, p.ExternalReferences)
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
	clone.ExternalReferences = cloneExternalReferences(p.ExternalReferences)
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
	// The destination is gated before its gaps are measured, not only the
	// source. Add normalizes what comes in, but Ensure, Get, and All hand back
	// mutable pointers, so p may already hold a value that is non-empty --
	// and so blocks this fill -- yet unpublishable, and therefore dropped
	// again at marshal. Measuring the gap first would lose a valid update to a
	// value that never reaches a reader.
	p.Description = NormalizeDescription(p.Description)
	p.Homepage = NormalizeHomepage(p.Homepage)
	p.Supplier = normalizedContact(p.Supplier)
	p.Originator = normalizedContact(p.Originator)
	if p.Description == "" {
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
	// Through the gated set merge, not a bare append: MergeFrom is exported
	// and the registry is not its only caller, so a hand-built package must
	// not install a rejected digest or a second, differently-spelled copy of
	// one already held.
	p.Digests = mergeDigestSet(p.Digests, src.Digests)
	// Licenses are a set too, and the declared/concluded distinction makes the
	// old first-wins behavior actively wrong: a source that concluded a
	// license and a source that read the declaration are two claims about one
	// package, and dropping either publishes a partial answer as a complete
	// one.
	p.Licenses = MergeLicenses(p.Licenses, src.Licenses)
	p.ExternalReferences = MergeExternalReferences(p.ExternalReferences, src.ExternalReferences)
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

// SetDetectionLicenses records detection-time license facts on dep, so
// consolidation can lift them into the package registry. No-op when dep is nil
// or licenses is empty.
//
// It now writes the typed DependencyNode.Licenses field rather than the
// metadata stash, which is the migration ADR-0037 calls for: the path for a
// metadata key is a typed field. Callers of this helper need no change, and
// payloads written by an older producer are still read — see
// DetectionLicenses.
func SetDetectionLicenses(dep *DependencyNode, licenses []PackageLicense) {
	if dep == nil || len(licenses) == 0 {
		return
	}
	dep.Licenses = MergeLicenses(dep.Licenses, licenses)
}

// DetectionLicenses returns the license facts recorded on dep at detection
// time: the typed field unioned with anything a producer left under the
// deprecated MetadataKeyDetectionLicenses stash.
//
// Both are read because the stash outlives this release. A node decoded from
// an older producer's payload, or built by a component still pinned to an
// earlier SDK, carries its licenses only in metadata, and a consumer that
// looked at the typed field alone would silently see a package with no
// licenses at all.
func DetectionLicenses(dep *DependencyNode) []PackageLicense {
	if dep == nil {
		return nil
	}
	licenses := dep.Licenses
	if dep.Metadata != nil {
		licenses = MergeLicenses(licenses, stashedDetectionLicenses(dep.Metadata[MetadataKeyDetectionLicenses]))
	}
	return MergeLicenses(nil, licenses)
}

// stashedDetectionLicenses reads the deprecated metadata stash whatever shape
// it arrived in.
//
// A typed assertion alone is not enough. Metadata is map[string]any, so a node
// that came off the wire holds the stash as []any of map[string]any -- the
// assertion fails, and the licenses a producer recorded vanish the first time
// the node crosses a process boundary. Re-decoding through the typed form
// costs a marshal on a path that only legacy payloads take, and the
// alternative is losing the data silently.
func stashedDetectionLicenses(value any) []PackageLicense {
	switch stashed := value.(type) {
	case nil:
		return nil
	case []PackageLicense:
		return stashed
	default:
		encoded, err := json.Marshal(stashed)
		if err != nil {
			return nil
		}
		var licenses []PackageLicense
		if err := json.Unmarshal(encoded, &licenses); err != nil {
			return nil
		}
		return licenses
	}
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
		Description: NormalizeDescription(dep.Description),
		Homepage:    NormalizeHomepage(dep.Homepage),
		Supplier:    normalizedContact(dep.Supplier),
		Originator:  normalizedContact(dep.Originator),
		// DetectionLicenses, not the typed field alone: a node from an older
		// producer carries its licenses in the deprecated metadata stash, and
		// seeding from the field alone would hand the registry a package with
		// no licenses.
		Licenses:           DetectionLicenses(dep),
		ExternalReferences: MergeExternalReferences(nil, dep.ExternalReferences),
		Digests:            mergeDigestSet(nil, dep.Digests),
		DetectedOrigins:    MergeOrigins(nil, dep.Origins),
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
