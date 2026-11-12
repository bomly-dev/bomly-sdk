package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/spdx/tools-golang/spdx/v2/common"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
	v30 "github.com/spdx/tools-golang/spdx/v3/v3_0"
)

// spdx30Codec reads and writes SPDX 3.0.1 in its JSON-LD serialization.
//
// Delegation. The SPDX 3 vocabulary, object model, JSON-LD serialization and
// validation are spdx/tools-golang's (package spdx/v3/v3_0), which this module
// already pins for SPDX 2.3 and which Syft's own SPDX 3 encoder uses. Nothing
// here spells an SPDX 3 term: every relationship type, hash algorithm,
// reference type and purpose is one of the library's generated values, or is
// read back through one.
//
// Encoding projects the document onto SPDX 2.3 with the same builder the 2.3
// codec uses, then converts it with the library's v3_0.From_v2_3. One
// projection, so the two SPDX encodings of one scan cannot disagree.
//
// Decoding has no library to delegate to: tools-golang converts 2.3 to 3.0
// and not back, and no maintained Go library reads SPDX 3 into anything
// else. lowerSPDX3 is the inverse step, written here against the library's
// typed model, and it lowers to the SPDX 2.3 model so that one set of rules
// (documentFromSPDX23) reads both versions. Where the inverse needs a
// vocabulary mapping it derives it from the library's own forward converter
// (spdx3_vocabulary.go) rather than transcribing one.
//
// The pinned library is a release candidate, v0.6.0-rc4; there is no final
// v0.6.0 yet. It has four defects this codec works around, each pinned by a
// test that fails once the library changes, so recheck all four when v0.6.0
// final ships:
//
//   - From_v2_3 keys SHA3 and BLAKE2b checksums with underscores (SHA3_256)
//     where SPDX 2.3 spells them with hyphens (SHA3-256), so those digests
//     convert with an empty, required algorithm (prepareSPDX23ForConversion;
//     TestSPDX3PublishesEveryDigestTheSDKPublishes).
//   - From_v2_3 keeps only the reference types in its own small maps and
//     drops every other external reference (carrySPDX3References).
//   - From_v2_3 leaves createdBy empty when every 2.3 creator is a tool,
//     which the library's own validation rejects (completeSPDX3CreatedBy).
//   - Both the converter and the serializer build element lists from map
//     iteration, so the output order and every minted identifier change from
//     run to run (nameSPDX3Elements, canonicalSPDX3JSON;
//     TestSPDX3EncodingIsDeterministic).
//
// The library's reader also panics on some malformed graphs, which is why
// both directions contain a panic at this boundary: license strings and
// whole documents here come from untrusted input.
type spdx30Codec struct{}

func (spdx30Codec) encodeJSON(doc *Document, opts EncodeOptions) (out []byte, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			out, err = nil, fmt.Errorf("encode spdx 3: %v", recovered)
		}
	}()

	spdx23 := buildSPDX23Document(doc)
	prepareSPDX23ForConversion(spdx23)

	var converted v30.Document
	v30.From_v2_3(*spdx23, &converted)
	if err := completeSPDX3Conversion(&converted, spdx23); err != nil {
		return nil, err
	}
	// Validated before writing, because ToJSON writes an invalid document
	// without complaint. preProcess runs the same fill-ins ToJSON performs.
	if err := converted.Validate(true); err != nil {
		return nil, fmt.Errorf("spdx 3 document failed validation: %w", err)
	}

	var buf bytes.Buffer
	if err := converted.ToJSON(&buf); err != nil {
		return nil, fmt.Errorf("serialize spdx 3: %w", err)
	}
	return canonicalSPDX3JSON(buf.Bytes(), opts.Pretty)
}

// prepareSPDX23ForConversion corrects the 2.3 projection where From_v2_3
// would otherwise misread it.
//
// Checksum algorithms: the converter's lookup keys write SPDX 2.3's
// hyphenated names with underscores, so "SHA3-256" finds nothing and the hash
// is written with no algorithm. Rewriting the hyphen is the whole difference
// between the two spellings, so no table is involved, and an algorithm without
// a hyphen is untouched.
//
// Download location and home page: SPDX 2.3 requires downloadLocation and
// fills an unknown one with NOASSERTION. SPDX 3 makes both optional anyURI
// properties with no such sentinel -- an unknown location is an absent one --
// so the sentinel is removed rather than published as a relative URI.
func prepareSPDX23ForConversion(doc *v23.Document) {
	for _, pkg := range doc.Packages {
		if pkg == nil {
			continue
		}
		for i := range pkg.PackageChecksums {
			pkg.PackageChecksums[i].Algorithm = spdx3ConverterChecksumKey(pkg.PackageChecksums[i].Algorithm)
		}
		if isSPDXSentinel(pkg.PackageDownloadLocation) {
			pkg.PackageDownloadLocation = ""
		}
		if isSPDXSentinel(pkg.PackageHomePage) {
			pkg.PackageHomePage = ""
		}
	}
	for i := range doc.ExternalDocumentReferences {
		ref := &doc.ExternalDocumentReferences[i]
		ref.Checksum.Algorithm = spdx3ConverterChecksumKey(ref.Checksum.Algorithm)
	}
}

// spdx3ConverterChecksumKey spells a 2.3 checksum algorithm the way
// From_v2_3's lookup expects it. See prepareSPDX23ForConversion.
func spdx3ConverterChecksumKey(algorithm common.ChecksumAlgorithm) common.ChecksumAlgorithm {
	return common.ChecksumAlgorithm(strings.ReplaceAll(string(algorithm), "-", "_"))
}

func isSPDXSentinel(value string) bool {
	value = strings.TrimSpace(value)
	return strings.EqualFold(value, "NOASSERTION") || strings.EqualFold(value, "NONE")
}

// completeSPDX3Conversion finishes what From_v2_3 leaves undone.
func completeSPDX3Conversion(d *v30.Document, spdx23 *v23.Document) error {
	sbom := spdx3ConvertedSBOM(d)
	if sbom == nil {
		return fmt.Errorf("spdx 3 conversion produced no sbom element")
	}
	packages := make(map[string]*v30.Package, len(spdx23.Packages))
	for _, element := range sbom.Elements {
		if pkg, ok := element.(*v30.Package); ok {
			packages[pkg.ID] = pkg
		}
	}
	for _, pkg := range spdx23.Packages {
		if pkg == nil {
			continue
		}
		if converted := packages[string(pkg.PackageSPDXIdentifier)]; converted != nil {
			carrySPDX3References(converted, pkg.PackageExternalReferences)
			// The converter leaves an empty list where it converted nothing, which
			// serializes as an empty array; absent says the same thing.
			if len(converted.ExternalIdentifiers) == 0 {
				converted.ExternalIdentifiers = nil
			}
		}
	}
	completeSPDX3CreatedBy(d)
	nameSPDX3Elements(d, sbom, spdx23)
	return nil
}

// spdx3ConvertedSBOM returns the software SBOM element From_v2_3 roots the
// document at.
func spdx3ConvertedSBOM(d *v30.Document) *v30.SBOM {
	for _, root := range d.RootElements {
		if sbom, ok := root.(*v30.SBOM); ok {
			return sbom
		}
	}
	return nil
}

// carrySPDX3References writes the external references From_v2_3 dropped.
//
// The converter keeps a reference only when its type is in one of two small
// lookup tables (purl, CPE, swid, four package managers, three security
// types); everything else -- a source document's website or issue tracker, an
// origin beyond the first -- is discarded with no trace in the output. SPDX 3
// has a home for each:
//
//   - An origin beyond the primary is an alternative download location, the
//     specification's own term for it.
//   - Any other reference is an ExternalRef of type "other", the value SPDX 3
//     defines for a type outside its vocabulary. SPDX 3 has no free-text type
//     field, so the 2.3 category and type it had ride in the comment, in the
//     same "bomly:" carrier the package comment uses, ahead of any comment
//     the reference had of its own.
//
// What the converter did carry is detected by locator rather than by
// re-deriving its tables, so a reference the library learns to convert stops
// being carried here without a change.
func carrySPDX3References(pkg *v30.Package, refs []*v23.PackageExternalReference) {
	for _, ref := range refs {
		if ref == nil {
			continue
		}
		locator := strings.TrimSpace(ref.Locator)
		if locator == "" || spdx3PackageCarriesLocator(pkg, locator) {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(ref.RefType), spdxOriginRefType) {
			pkg.ExternalRefs = append(pkg.ExternalRefs, &v30.ExternalRef{
				Type:     v30.ExternalRefType_AltDownloadLocation,
				Locators: []string{locator},
			})
			continue
		}
		pkg.ExternalRefs = append(pkg.ExternalRefs, &v30.ExternalRef{
			Type:     v30.ExternalRefType_Other,
			Locators: []string{locator},
			Comment:  spdx3ReferenceCarrier(ref.Category, ref.RefType, ref.ExternalRefComment),
		})
	}
}

func spdx3PackageCarriesLocator(pkg *v30.Package, locator string) bool {
	if string(pkg.PackageURL) == locator {
		return true
	}
	for _, identifier := range pkg.ExternalIdentifiers {
		if identifier != nil && identifier.GetIdentifier() == locator {
			return true
		}
	}
	for _, ref := range pkg.ExternalRefs {
		if ref == nil {
			continue
		}
		for _, l := range ref.GetLocators() {
			if l == locator {
				return true
			}
		}
	}
	return false
}

// spdx3ReferenceCarrierPrefix opens the comment of an "other" ExternalRef
// that carries an SPDX 2.3 category and type. The first line is the carrier;
// anything after it is the reference's own comment.
const spdx3ReferenceCarrierPrefix = "bomly:"

func spdx3ReferenceCarrier(category, refType, comment string) string {
	carrier := spdx3ReferenceCarrierPrefix + "category=" + strings.TrimSpace(category) + ";type=" + strings.TrimSpace(refType)
	if comment = strings.TrimSpace(comment); comment != "" {
		carrier += "\n" + comment
	}
	return carrier
}

// parseSPDX3ReferenceCarrier reads a carrier written by spdx3ReferenceCarrier.
// ok is false for a comment that carries none, which is every comment a
// document Bomly did not write has.
func parseSPDX3ReferenceCarrier(comment string) (category, refType, rest string, ok bool) {
	first, rest, _ := strings.Cut(comment, "\n")
	if !strings.HasPrefix(strings.TrimSpace(first), spdx3ReferenceCarrierPrefix) {
		return "", "", comment, false
	}
	category = parseSPDXCommentField(first, "category")
	refType = parseSPDXCommentField(first, "type")
	if category == "" || refType == "" {
		return "", "", comment, false
	}
	return category, refType, strings.TrimSpace(rest), true
}

// completeSPDX3CreatedBy names an agent when the conversion found none.
//
// SPDX 3 requires at least one createdBy agent, and From_v2_3 reads agents
// only from Person and Organization creators: a 2.3 document credited to a
// tool alone -- every Bomly scan without a configured manufacturer -- converts
// to a document the library's own validation rejects. The tool that produced
// the document is the agent that created it, and SPDX 3 has the class for
// that: SoftwareAgent.
//
// Only the producer. The 2.3 creators list the producing tool first
// (documentTools guarantees it) followed by the tools the source documents
// credited, and those contributed to this document without creating it;
// createdUsing keeps naming every one of them.
func completeSPDX3CreatedBy(d *v30.Document) {
	info, ok := d.CreationInfo.(*v30.CreationInfo)
	if !ok || info == nil || len(info.CreatedBy) > 0 {
		return
	}
	for _, tool := range info.CreatedUsing {
		if isNilElement(tool) || strings.TrimSpace(tool.GetName()) == "" {
			continue
		}
		info.CreatedBy = append(info.CreatedBy, &v30.SoftwareAgent{
			Name:         tool.GetName(),
			CreationInfo: info,
		})
		return
	}
}

// nameSPDX3Elements gives every element an identifier derived from what it
// is, and folds duplicate agents and listed licenses into one element each.
//
// From_v2_3 leaves most elements without an identifier and the serializer
// mints one per element in traversal order, which follows map iteration:
// the same scan written twice came out with different identifiers for the
// same relationships and licenses, so neither a diff nor a golden could
// compare two exports. The converter also builds a fresh agent per package
// for a shared supplier and a fresh license per occurrence of an identifier,
// so a dependency tree under one MIT-licensed vendor published that vendor and
// that license once per package.
//
// Names come from content -- a relationship from its subject and type, a
// listed license from its identifier -- and are allocated in the order of the
// 2.3 projection, which is deterministic, so the same document always names
// its elements the same way. Identifiers the conversion already set (packages,
// LicenseRef licenses, the specification's individual license values) are
// kept.
func nameSPDX3Elements(d *v30.Document, sbom *v30.SBOM, spdx23 *v23.Document) {
	n := &spdx3Namer{
		ids:      newSPDXIDAllocator(len(sbom.Elements)),
		seen:     make(map[any]struct{}, len(sbom.Elements)),
		agents:   make(map[string]v30.AnyAgent),
		licenses: make(map[string]v30.AnyLicenseInfo),
	}
	// Identifiers the conversion set are reserved first, so a minted name can
	// never collide with one.
	for _, element := range sbom.Elements {
		if element != nil && element.GetID() != "" && !strings.Contains(element.GetID(), ":") {
			n.ids.assigned[element.GetID()] = struct{}{}
		}
	}

	n.name(sbom, "SBOM")
	if info, ok := d.CreationInfo.(*v30.CreationInfo); ok && info != nil {
		for i, agent := range info.CreatedBy {
			info.CreatedBy[i] = n.agent(agent)
		}
		for _, tool := range info.CreatedUsing {
			n.name(tool, "Tool-"+tool.GetName())
		}
	}
	d.DataLicense = n.license(d.DataLicense, "DataLicense")

	relationships := make(map[v30.AnyElement][]v30.AnyRelationship)
	for _, element := range sbom.Elements {
		if rel, ok := element.(v30.AnyRelationship); ok && rel != nil {
			relationships[rel.GetFrom()] = append(relationships[rel.GetFrom()], rel)
		}
	}
	byID := make(map[string]*v30.Package, len(sbom.Elements))
	for _, element := range sbom.Elements {
		if pkg, ok := element.(*v30.Package); ok {
			byID[pkg.ID] = pkg
		}
	}
	for _, pkg23 := range spdx23.Packages {
		if pkg23 == nil {
			continue
		}
		pkg := byID[string(pkg23.PackageSPDXIdentifier)]
		if pkg == nil {
			continue
		}
		if !isNilElement(pkg.SuppliedBy) {
			pkg.SuppliedBy = n.agent(pkg.SuppliedBy)
		}
		for i, agent := range pkg.OriginatedBy {
			pkg.OriginatedBy[i] = n.agent(agent)
		}
		n.relationships(pkg.ID, relationships[pkg])
		delete(relationships, pkg)
	}
	// Anything left -- a relationship whose subject is not a package, which
	// Bomly does not write today -- is named in a stable order too.
	var rest []v30.AnyRelationship
	for _, rels := range relationships {
		rest = append(rest, rels...)
	}
	n.relationships("Element", rest)

	// The converter also lists every element it built in the SBOM's and the
	// document's element lists, the library's shared license values among
	// them, and ToJSON walks those lists too. Each list gets the
	// per-document values license() handed out, so nothing reachable from
	// this document is shared with another.
	sbom.Elements = n.ownElements(sbom.Elements)
	d.Elements = n.ownElements(d.Elements)
}

func (n *spdx3Namer) ownElements(elements v30.ElementList) v30.ElementList {
	for i, element := range elements {
		if shared, ok := element.(*v30.IndividualLicensingInfo); ok && shared != nil {
			if own, ok := n.license(shared, "").(v30.AnyElement); ok {
				elements[i] = own
			}
		}
	}
	return elements
}

type spdx3Namer struct {
	ids      *spdxIDAllocator
	seen     map[any]struct{}
	agents   map[string]v30.AnyAgent
	licenses map[string]v30.AnyLicenseInfo
}

// name sets an element's identifier once. An identifier already present is
// kept.
func (n *spdx3Namer) name(element interface {
	GetID() string
	SetID(string)
}, raw string) {
	if isNilElement(element) {
		return
	}
	if _, done := n.seen[element]; done {
		return
	}
	n.seen[element] = struct{}{}
	if element.GetID() != "" {
		return
	}
	element.SetID(n.ids.allocate(raw))
}

// agent returns the one element standing for this agent, naming it.
func (n *spdx3Namer) agent(agent v30.AnyAgent) v30.AnyAgent {
	if isNilElement(agent) {
		return agent
	}
	kind := spdx3TypeName(agent)
	key := kind + "\x00" + agent.GetName() + "\x00" + spdx3IdentifierKey(agent.GetExternalIdentifiers())
	if existing, ok := n.agents[key]; ok {
		return existing
	}
	n.agents[key] = agent
	n.name(agent, kind+"-"+agent.GetName())
	return agent
}

func spdx3IdentifierKey(identifiers v30.ExternalIdentifierList) string {
	parts := make([]string, 0, len(identifiers))
	for _, identifier := range identifiers {
		if identifier == nil {
			continue
		}
		typ := identifier.GetType()
		parts = append(parts, typ.GetID()+"="+identifier.GetIdentifier())
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// relationships names a subject's relationships and the license trees they
// point at, ordered by type so the allocation order does not depend on the
// converter's map iteration.
func (n *spdx3Namer) relationships(subject string, rels []v30.AnyRelationship) {
	type keyed struct {
		key string
		rel v30.AnyRelationship
	}
	ordered := make([]keyed, 0, len(rels))
	for _, rel := range rels {
		ordered = append(ordered, keyed{key: spdx3RelationshipKey(rel), rel: rel})
	}
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].key < ordered[j].key })
	for _, entry := range ordered {
		rel := entry.rel
		typ := rel.GetType()
		raw := "Relationship-" + subject + "-" + spdx3Tail(typ.GetID())
		if scoped, ok := rel.(v30.AnyLifecycleScopedRelationship); ok {
			scope := scoped.GetScope()
			raw += "-" + spdx3Tail(scope.GetID())
		}
		n.name(rel, raw)
		to := rel.GetTo()
		for i, target := range to {
			if license, ok := target.(v30.AnyLicenseInfo); ok {
				to[i] = n.license(license, rel.GetID()+"-license")
			}
		}
	}
}

// spdx3RelationshipKey orders a subject's relationships by what they say,
// with the targets as the tie-break.
func spdx3RelationshipKey(rel v30.AnyRelationship) string {
	typ := rel.GetType()
	key := typ.GetID()
	if scoped, ok := rel.(v30.AnyLifecycleScopedRelationship); ok {
		scope := scoped.GetScope()
		key += "\x00" + scope.GetID()
	}
	for _, target := range rel.GetTo() {
		if license, ok := target.(v30.AnyLicenseInfo); ok {
			if expression, rendered := renderSPDX3License(license); rendered {
				key += "\x00" + expression
				continue
			}
		}
		if !isNilElement(target) {
			key += "\x00" + target.GetID()
		}
	}
	return key
}

// license returns the one element standing for this license tree, naming
// every node in it. Listed licenses and listed exceptions are folded by
// identifier; compound nodes are named by their position under raw.
func (n *spdx3Namer) license(license v30.AnyLicenseInfo, raw string) v30.AnyLicenseInfo {
	if isNilElement(license) {
		return license
	}
	switch l := license.(type) {
	case *v30.ListedLicense:
		key := "ListedLicense-" + l.Name
		if existing, ok := n.licenses[key]; ok {
			return existing
		}
		n.licenses[key] = l
		n.name(l, key)
	case *v30.ConjunctiveLicenseSet:
		n.name(l, raw)
		for i, member := range l.Members {
			l.Members[i] = n.license(member, fmt.Sprintf("%s-%d", l.ID, i))
		}
	case *v30.DisjunctiveLicenseSet:
		n.name(l, raw)
		for i, member := range l.Members {
			l.Members[i] = n.license(member, fmt.Sprintf("%s-%d", l.ID, i))
		}
	case *v30.OrLaterOperator:
		n.name(l, raw)
		if subject, ok := n.license(l.SubjectLicense, l.ID+"-subject").(v30.AnyLicense); ok {
			l.SubjectLicense = subject
		}
	case *v30.WithAdditionOperator:
		n.name(l, raw)
		if subject, ok := n.license(l.SubjectExtendableLicense, l.ID+"-subject").(v30.AnyExtendableLicense); ok {
			l.SubjectExtendableLicense = subject
		}
		l.SubjectAddition = n.addition(l.SubjectAddition, l.ID+"-addition")
	case *v30.IndividualLicensingInfo:
		// NoAssertionLicense and NoneLicense are package variables in the
		// library, and ToJSON writes this document's creationInfo into any
		// element that has none. Publishing the shared value would mutate a
		// global: the next document would carry this one's creation info,
		// and two concurrent encodes would race. A per-document value with
		// the same IRI says the same thing.
		key := "IndividualLicensingInfo-" + l.ID
		if existing, ok := n.licenses[key]; ok {
			return existing
		}
		own := &v30.IndividualLicensingInfo{ID: l.ID, Name: l.Name}
		n.licenses[key] = own
		n.seen[own] = struct{}{}
		return own
	default:
		n.name(license, raw)
	}
	return license
}

func (n *spdx3Namer) addition(addition v30.AnyLicenseAddition, raw string) v30.AnyLicenseAddition {
	if isNilElement(addition) {
		return addition
	}
	if listed, ok := addition.(*v30.ListedLicenseException); ok {
		key := "ListedLicenseException-" + listed.AdditionText
		if existing, ok := n.licenses[key]; ok {
			if folded, ok := existing.(v30.AnyLicenseAddition); ok {
				return folded
			}
		}
		if info, ok := addition.(v30.AnyLicenseInfo); ok {
			n.licenses[key] = info
		}
		n.name(listed, key)
		return listed
	}
	n.name(addition, raw)
	return addition
}

// canonicalSPDX3JSON orders the serialized graph.
//
// The serializer walks an object graph whose collections were filled from
// map iteration, so the @graph array and every collection's element list come
// out in a different order on each run. With every identifier fixed by
// nameSPDX3Elements, sorting the graph by identifier and each element list
// lexically is the whole of the remaining nondeterminism; every other list
// (rootElement, a relationship's targets, createdBy) already follows the 2.3
// projection's order and is left as it is. Object keys are written sorted by
// encoding/json, as the 2.3 encoder writes them.
func canonicalSPDX3JSON(raw []byte, pretty bool) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("canonicalize spdx 3: %w", err)
	}
	graph, _ := document["@graph"].([]any)
	for _, node := range graph {
		object, ok := node.(map[string]any)
		if !ok {
			continue
		}
		if elements, ok := object["element"].([]any); ok {
			sort.SliceStable(elements, func(i, j int) bool {
				return fmt.Sprint(elements[i]) < fmt.Sprint(elements[j])
			})
		}
	}
	sort.SliceStable(graph, func(i, j int) bool {
		return spdx3NodeKey(graph[i]) < spdx3NodeKey(graph[j])
	})
	return marshalJSON(document, pretty)
}

func spdx3NodeKey(node any) string {
	object, ok := node.(map[string]any)
	if !ok {
		return ""
	}
	for _, key := range []string{"spdxId", "@id"} {
		if id, ok := object[key].(string); ok {
			return id
		}
	}
	return ""
}

// spdx3Tail is the local name of an SPDX 3 vocabulary IRI: the generated
// values' identifiers are "https://spdx.org/rdf/3.0.1/terms/<Profile>/<Class>/<name>".
func spdx3Tail(iri string) string {
	if i := strings.LastIndexAny(iri, "/#"); i >= 0 {
		return iri[i+1:]
	}
	return iri
}

// spdx3TypeName names an element's class, for identifiers.
func spdx3TypeName(element any) string {
	name := fmt.Sprintf("%T", element)
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// isNilElement reports a nil interface or a typed nil pointer inside one; the
// converter hands back both.
func isNilElement(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	return v.Kind() == reflect.Pointer && v.IsNil()
}
