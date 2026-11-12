package sbom

import (
	"strings"
	"sync"

	"github.com/spdx/tools-golang/spdx/v2/common"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
	v30 "github.com/spdx/tools-golang/spdx/v3/v3_0"

	"github.com/bomly-dev/bomly-sdk/model"
)

// spdx3Vocabulary maps SPDX 3 vocabulary values back to the SPDX 2.3 terms
// the decoder lowers them to.
//
// None of it is written out by hand. tools-golang owns the 2.3 -> 3.0 mapping
// (v3_0.From_v2_3) and keeps it in unexported tables, and offers no inverse.
// Copying those tables here would be the transcription the delegation rule
// forbids: correct the day it was written and silently lossy the day the
// library or the specification grew. Instead each inverse is read off the
// library's own forward converter, once, by converting a probe document that
// carries one instance of every 2.3 term this package can name:
//
//   - checksum algorithms: every member of the SDK's digest registry with an
//     SPDX spelling (model.DigestAlgorithms), so the registry stays the one
//     list of algorithms;
//   - external reference types: every type tools-golang declares for SPDX 2.3
//     Annex F, by its constant.
//
// A 2.3 term the converter does not map simply produces no inverse entry,
// and the decoder treats the 3.0 value as foreign. TestSPDX3VocabularyIsDerived
// FromTheLibrary pins what the derivation finds, so a library change shows up
// as a named test failure rather than as a quiet change in decoded output.
type spdx3Vocabulary struct {
	// checksums maps a HashAlgorithm IRI to its SPDX 2.3 checksum spelling.
	checksums map[string]common.ChecksumAlgorithm
	// references maps an ExternalIdentifierType or ExternalRefType IRI to
	// the SPDX 2.3 category and type it was converted from.
	references map[string]spdx3ReferenceTerm
}

type spdx3ReferenceTerm struct {
	category string
	refType  string
}

// spdx3AnnexFReferenceTypes are the SPDX 2.3 Annex F reference types, each
// named by the constant tools-golang declares for it. The library has no
// slice of them, so they are listed; the values are the library's.
var spdx3AnnexFReferenceTypes = []spdx3ReferenceTerm{
	{common.CategorySecurity, common.TypeSecurityCPE23Type},
	{common.CategorySecurity, common.TypeSecurityCPE22Type},
	{common.CategorySecurity, common.TypeSecurityAdvisory},
	{common.CategorySecurity, common.TypeSecurityFix},
	{common.CategorySecurity, common.TypeSecurityUrl},
	{common.CategorySecurity, common.TypeSecuritySwid},
	{common.CategoryPackageManager, common.TypePackageManagerMavenCentral},
	{common.CategoryPackageManager, common.TypePackageManagerNpm},
	{common.CategoryPackageManager, common.TypePackageManagerNuGet},
	{common.CategoryPackageManager, common.TypePackageManagerBower},
	{common.CategoryPackageManager, common.TypePackageManagerPURL},
	{common.CategoryPersistentId, common.TypePersistentIdSwh},
	{common.CategoryPersistentId, common.TypePersistentIdGitoid},
}

var (
	spdx3VocabularyOnce  sync.Once
	spdx3VocabularyValue spdx3Vocabulary
)

// spdx3VocabularyTerms returns the derived inverse vocabulary.
func spdx3VocabularyTerms() spdx3Vocabulary {
	spdx3VocabularyOnce.Do(func() {
		spdx3VocabularyValue = deriveSPDX3Vocabulary()
	})
	return spdx3VocabularyValue
}

func deriveSPDX3Vocabulary() (vocabulary spdx3Vocabulary) {
	vocabulary = spdx3Vocabulary{
		checksums:  make(map[string]common.ChecksumAlgorithm),
		references: make(map[string]spdx3ReferenceTerm),
	}
	// The derivation runs library code; a panic in it must not take a scan
	// down. A vocabulary that could not be derived decodes every value as
	// foreign, which loses precision, not data.
	defer func() {
		if recover() != nil {
			vocabulary = spdx3Vocabulary{
				checksums:  map[string]common.ChecksumAlgorithm{},
				references: map[string]spdx3ReferenceTerm{},
			}
		}
	}()

	// One package per term, so each converted package says which term it
	// came from by its identifier.
	probe := v23.Document{
		SPDXVersion:       v23.Version,
		DataLicense:       v23.DataLicense,
		SPDXIdentifier:    "DOCUMENT",
		DocumentName:      "vocabulary",
		DocumentNamespace: "https://bomly.dev/spdx/vocabulary",
		CreationInfo: &v23.CreationInfo{
			Creators: []common.Creator{{CreatorType: "Organization", Creator: "bomly"}},
			Created:  "2000-01-01T00:00:00Z",
		},
	}
	checksumOf := map[string]common.ChecksumAlgorithm{}
	for _, algorithm := range model.DigestAlgorithms() {
		spelling := algorithm.SPDXName()
		if spelling == "" {
			continue
		}
		id := "checksum-" + sanitizeSPDXID(spelling)
		checksumOf[id] = common.ChecksumAlgorithm(spelling)
		probe.Packages = append(probe.Packages, &v23.Package{
			PackageName:           id,
			PackageSPDXIdentifier: common.ElementID(id),
			PackageChecksums: []common.Checksum{{
				Algorithm: spdx3ConverterChecksumKey(common.ChecksumAlgorithm(spelling)),
				Value:     "00",
			}},
		})
	}
	referenceOf := map[string]spdx3ReferenceTerm{}
	for _, term := range spdx3AnnexFReferenceTypes {
		id := "reference-" + sanitizeSPDXID(term.refType)
		referenceOf[id] = term
		probe.Packages = append(probe.Packages, &v23.Package{
			PackageName:           id,
			PackageSPDXIdentifier: common.ElementID(id),
			PackageExternalReferences: []*v23.PackageExternalReference{{
				Category: term.category,
				RefType:  term.refType,
				// Not a valid URI, on purpose: the converter moves a purl that
				// parses as one out of the identifier list into packageUrl,
				// where its identifier type can no longer be read. Every
				// other type takes the locator as it is.
				Locator: "%zz",
			}},
		})
	}

	var converted v30.Document
	v30.From_v2_3(probe, &converted)
	sbom := spdx3ConvertedSBOM(&converted)
	if sbom == nil {
		return vocabulary
	}
	for _, element := range sbom.Elements {
		pkg, ok := element.(*v30.Package)
		if !ok {
			continue
		}
		if spelling, ok := checksumOf[pkg.ID]; ok {
			for _, method := range pkg.VerifiedUsing {
				if hash, ok := method.(*v30.Hash); ok && hash.Algorithm.GetID() != "" {
					vocabulary.checksums[hash.Algorithm.GetID()] = spelling
				}
			}
			continue
		}
		term, ok := referenceOf[pkg.ID]
		if !ok {
			continue
		}
		for _, identifier := range pkg.ExternalIdentifiers {
			if identifier == nil {
				continue
			}
			typ := identifier.GetType()
			vocabulary.references[typ.GetID()] = term
		}
		for _, ref := range pkg.ExternalRefs {
			if ref == nil {
				continue
			}
			typ := ref.GetType()
			vocabulary.references[typ.GetID()] = term
		}
	}
	// The Bomly-defined origin type is published as an alternative download
	// location (carrySPDX3References), so it reads back as that type -- and
	// the 2.3 reader then declines it as origin-derived, the same rule the
	// CycloneDX reader applies to vcs and distribution references.
	vocabulary.references[v30.ExternalRefType_AltDownloadLocation.GetID()] = spdx3ReferenceTerm{
		category: common.CategoryOther,
		refType:  spdxOriginRefType,
	}
	return vocabulary
}

// spdx3ChecksumAlgorithm returns the SPDX 2.3 spelling of an SPDX 3 hash
// algorithm, or false for one the SDK has no member for.
func spdx3ChecksumAlgorithm(algorithm v30.HashAlgorithm) (common.ChecksumAlgorithm, bool) {
	spelling, ok := spdx3VocabularyTerms().checksums[algorithm.GetID()]
	return spelling, ok
}

// spdx3ReferenceTermFor returns the SPDX 2.3 category and type an SPDX 3
// reference type lowers to.
//
// A type outside the derived vocabulary is foreign -- one SPDX 3 defines and
// 2.3 does not, such as vcs or issueTracker -- and keeps its SPDX 3 name as
// the type under category OTHER, the 2.3 category for exactly that. The
// model's reference vocabulary is open by design, so the name survives a
// round trip rather than being folded into a 2.3 type it is not.
func spdx3ReferenceTermFor(iri string) spdx3ReferenceTerm {
	if term, ok := spdx3VocabularyTerms().references[iri]; ok {
		return term
	}
	return spdx3ReferenceTerm{category: common.CategoryOther, refType: spdx3Tail(iri)}
}

// spdx3PurposeName lowers an SPDX 3 software purpose to the 2.3 spelling:
// "operatingSystem" becomes "OPERATING-SYSTEM". Purposes are written in
// lowerCamelCase in SPDX 3 and in upper case with hyphens in 2.3; the change
// is spelling only, so it is a rule rather than a table, and a purpose 2.3
// lacks keeps its name for the component-type reader to classify.
func spdx3PurposeName(purpose v30.SoftwarePurpose) string {
	tail := spdx3Tail(purpose.GetID())
	if tail == "" {
		return ""
	}
	var b strings.Builder
	for i, r := range tail {
		if r >= 'A' && r <= 'Z' && i > 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return strings.ToUpper(b.String())
}
