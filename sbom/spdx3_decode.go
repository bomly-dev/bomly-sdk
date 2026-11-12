package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spdx/tools-golang/spdx/v2/common"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
	v30 "github.com/spdx/tools-golang/spdx/v3/v3_0"
)

func (spdx30Codec) decodeJSON(data []byte) (doc *Document, err error) {
	// The library's JSON-LD reader panics on some malformed graphs (a
	// vocabulary value given as an element, for one), and this is untrusted
	// input: the panic is contained here and reported as malformed input.
	defer func() {
		if recovered := recover(); recovered != nil {
			doc, err = nil, fmt.Errorf("%w: spdx 3: %v", ErrMalformedJSON, recovered)
		}
	}()
	defined, err := defineSPDX3ListedReferences(data)
	if err != nil {
		return nil, fmt.Errorf("%w: spdx 3: %v", ErrMalformedJSON, err)
	}
	var parsed v30.Document
	if err := parsed.FromJSON(bytes.NewReader(defined)); err != nil {
		return nil, fmt.Errorf("%w: spdx 3: %v", ErrMalformedJSON, err)
	}
	return documentFromSPDX23(lowerSPDX3(&parsed)), nil
}

// spdx3ListedReferenceProperties are the license properties of the SPDX
// 3.0.1 JSON-LD context whose value names a license or exception element,
// with whether the element named is an exception.
var spdx3ListedReferenceProperties = map[string]bool{
	"to":                               false,
	"dataLicense":                      false,
	"expandedlicensing_member":         false,
	"expandedlicensing_subjectLicense": false,
	"expandedlicensing_subjectExtendableLicense": false,
	"expandedlicensing_subjectAddition":          true,
}

// defineSPDX3ListedReferences adds a definition for every SPDX License List
// license or exception the document names by IRI without defining.
//
// A producer may name a listed license by its License List IRI
// (https://spdx.org/licenses/MIT) instead of defining an element for it. The
// pinned library's reader cannot resolve an identifier the graph does not
// define -- its only placeholder type for one satisfies no element interface
// -- so it rejected such a document outright, over a license reference. The
// IRI says everything a definition would: which list entry it is. So a
// minimal definition is added before reading, typed as the position it was
// named in requires (an exception after WITH, a license elsewhere), and the
// renderer reads the identifier back from the IRI. Only license properties
// are considered and only the License List namespace, so no other
// reference is altered. When the library can resolve external identifiers,
// this becomes a no-op: nothing is added for a document that defines what it
// names.
func defineSPDX3ListedReferences(data []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	graph, _ := document["@graph"].([]any)
	defined := make(map[string]struct{}, len(graph))
	var creationInfo any
	for _, node := range graph {
		object, ok := node.(map[string]any)
		if !ok {
			continue
		}
		if id := spdx3NodeKey(object); id != "" {
			defined[id] = struct{}{}
		}
		if creationInfo == nil {
			creationInfo = object["creationInfo"]
		}
	}

	named := make(map[string]bool) // IRI -> is an exception
	var order []string
	for _, node := range graph {
		object, ok := node.(map[string]any)
		if !ok {
			continue
		}
		for property, exception := range spdx3ListedReferenceProperties {
			for _, iri := range spdx3ReferenceValues(object[property]) {
				if !strings.HasPrefix(iri, spdxListedLicenseNamespace) || len(iri) == len(spdxListedLicenseNamespace) {
					continue
				}
				if _, ok := defined[iri]; ok {
					continue
				}
				if _, seen := named[iri]; !seen {
					order = append(order, iri)
				}
				named[iri] = named[iri] || exception
			}
		}
	}
	if len(order) == 0 {
		return data, nil
	}
	sort.Strings(order)
	for _, iri := range order {
		identifier := strings.TrimPrefix(iri, spdxListedLicenseNamespace)
		definition := map[string]any{
			"spdxId":       iri,
			"name":         identifier,
			"creationInfo": creationInfo,
		}
		if named[iri] {
			definition["type"] = "expandedlicensing_ListedLicenseException"
			definition["expandedlicensing_additionText"] = identifier
		} else {
			definition["type"] = "expandedlicensing_ListedLicense"
		}
		if creationInfo == nil {
			delete(definition, "creationInfo")
		}
		graph = append(graph, definition)
	}
	document["@graph"] = graph
	return json.Marshal(document)
}

// spdx3ReferenceValues reads a property that names one element or a list of
// them.
func spdx3ReferenceValues(value any) []string {
	switch v := value.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, entry := range v {
			if s, ok := entry.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// lowerSPDX3 rewrites an SPDX 3 document as the SPDX 2.3 document it would
// have been converted from, so the 2.3 reader -- which owns every rule about
// what an SPDX package, license, reference or creator means to Bomly -- reads
// both versions. It is the inverse of v3_0.From_v2_3, which tools-golang does
// not provide; see spdx30Codec.
//
// What 2.3 cannot hold is not invented: a relationship that is not a
// dependency, a description or a license is dropped, as the 2.3 reader drops
// one, and an element that is not a package is read only where a package
// points at it.
func lowerSPDX3(d *v30.Document) *v23.Document {
	l := newSPDX3Lowering(d)

	out := &v23.Document{
		SPDXVersion:       v23.Version,
		DataLicense:       v23.DataLicense,
		SPDXIdentifier:    common.ElementID("DOCUMENT"),
		DocumentName:      d.Name,
		DocumentNamespace: spdx3DocumentNamespace(d.ID),
		DocumentComment:   d.Comment,
		CreationInfo:      lowerSPDX3CreationInfo(d.CreationInfo),
	}
	if license, ok := renderSPDX3License(d.DataLicense); ok {
		out.DataLicense = license
	}
	for _, imported := range d.Imports {
		if ref, ok := lowerSPDX3Import(imported); ok {
			out.ExternalDocumentReferences = append(out.ExternalDocumentReferences, ref)
		}
	}

	// Packages first, in document order, so identifiers are allocated the
	// same way every time the same document is read.
	for _, element := range d.Elements {
		if pkg, ok := element.(v30.AnyPackage); ok && !isNilElement(pkg) {
			out.Packages = append(out.Packages, l.lowerPackage(pkg))
		}
	}
	for _, element := range d.Elements {
		if custom, ok := element.(*v30.CustomLicense); ok && custom != nil {
			if other := lowerSPDX3CustomLicense(custom); other != nil {
				out.OtherLicenses = append(out.OtherLicenses, other)
			}
		}
	}
	out.Relationships = append(out.Relationships, l.describes(d)...)
	for _, element := range d.Elements {
		rel, ok := element.(v30.AnyRelationship)
		if !ok || isNilElement(rel) {
			continue
		}
		out.Relationships = append(out.Relationships, l.lowerRelationship(rel)...)
	}
	l.applyLicenses(d.Elements)
	return out
}

// spdx3DocumentNamespace recovers the 2.3 namespace From_v2_3 turned into the
// document's identifier by appending "#" for its elements to hang off.
func spdx3DocumentNamespace(id string) string {
	return strings.TrimSuffix(strings.TrimSpace(id), "#")
}

type spdx3Lowering struct {
	ids      *spdxIDAllocator
	idOf     map[v30.AnyElement]common.ElementID
	packages map[v30.AnyElement]*v23.Package
	expand   func(string) string
	document string
}

func newSPDX3Lowering(d *v30.Document) *spdx3Lowering {
	prefixes := make(map[string]string, len(d.NamespaceMaps))
	for _, entry := range d.NamespaceMaps {
		if entry == nil {
			continue
		}
		prefixes[entry.GetPrefix()] = string(entry.GetNamespace())
	}
	return &spdx3Lowering{
		ids:      newSPDXIDAllocator(len(d.Elements)),
		idOf:     make(map[v30.AnyElement]common.ElementID, len(d.Elements)),
		packages: make(map[v30.AnyElement]*v23.Package, len(d.Elements)),
		document: strings.TrimSpace(d.ID),
		// A compact identifier ("SPDXRef:pkg-x") is expanded through the
		// document's namespace map, which is what the prefix means; the
		// reader keeps identifiers exactly as written.
		expand: func(id string) string {
			prefix, rest, ok := strings.Cut(id, ":")
			if !ok {
				return id
			}
			if namespace, known := prefixes[prefix]; known {
				return namespace + rest
			}
			return id
		},
	}
}

// elementID names an element in the lowered document.
//
// An element under the document's own namespace keeps its local part, which
// for a document Bomly wrote is the 2.3 identifier it was converted from. Any
// other identifier -- a full IRI from another producer -- is made a valid 2.3
// idstring. Either way the allocator keeps the result unique.
func (l *spdx3Lowering) elementID(element v30.AnyElement) common.ElementID {
	if id, ok := l.idOf[element]; ok {
		return id
	}
	raw := l.expand(strings.TrimSpace(element.GetID()))
	if l.document != "" && strings.HasPrefix(raw, l.document) {
		raw = strings.TrimLeft(strings.TrimPrefix(raw, l.document), "#/")
	}
	if raw == "" {
		raw = spdx3TypeName(element)
	}
	id := common.ElementID(l.ids.allocate(raw))
	l.idOf[element] = id
	return id
}

func (l *spdx3Lowering) lowerPackage(pkg v30.AnyPackage) *v23.Package {
	out := &v23.Package{
		PackageName:           pkg.GetName(),
		PackageSPDXIdentifier: l.elementID(pkg),
		PackageVersion:        pkg.GetVersion(),
		PackageSummary:        pkg.GetSummary(),
		PackageDescription:    pkg.GetDescription(),
		PackageComment:        pkg.GetComment(),
		PackageHomePage:       string(pkg.GetHomePage()),
		PackageSourceInfo:     pkg.GetSourceInfo(),
		PackageCopyrightText:  pkg.GetCopyrightText(),
		PrimaryPackagePurpose: spdx3PurposeName(pkg.GetPrimaryPurpose()),
		PackageSupplier:       lowerSPDX3Supplier(pkg.GetSuppliedBy()),
		PackageChecksums:      lowerSPDX3Checksums(pkg.GetVerifiedUsing()),
		// The 2.3 meaning of an absent download location.
		PackageDownloadLocation: "NOASSERTION",
	}
	if location := strings.TrimSpace(string(pkg.GetDownloadLocation())); location != "" {
		out.PackageDownloadLocation = location
	}
	if originators := pkg.GetOriginatedBy(); len(originators) > 0 {
		out.PackageOriginator = lowerSPDX3Originator(originators[0])
	}
	if purl := strings.TrimSpace(string(pkg.GetPackageURL())); purl != "" {
		out.PackageExternalReferences = append(out.PackageExternalReferences, &v23.PackageExternalReference{
			Category: common.CategoryPackageManager,
			RefType:  common.TypePackageManagerPURL,
			Locator:  purl,
		})
	}
	for _, identifier := range pkg.GetExternalIdentifiers() {
		if identifier == nil || strings.TrimSpace(identifier.GetIdentifier()) == "" {
			continue
		}
		typ := identifier.GetType()
		term := spdx3ReferenceTermFor(typ.GetID())
		out.PackageExternalReferences = append(out.PackageExternalReferences, &v23.PackageExternalReference{
			Category:           term.category,
			RefType:            term.refType,
			Locator:            strings.TrimSpace(identifier.GetIdentifier()),
			ExternalRefComment: identifier.GetComment(),
		})
	}
	for _, ref := range pkg.GetExternalRefs() {
		if ref == nil {
			continue
		}
		typ := ref.GetType()
		term := spdx3ReferenceTermFor(typ.GetID())
		comment := ref.GetComment()
		if typ == v30.ExternalRefType_Other {
			if category, refType, rest, ok := parseSPDX3ReferenceCarrier(comment); ok {
				term = spdx3ReferenceTerm{category: category, refType: refType}
				comment = rest
			}
		}
		for _, locator := range ref.GetLocators() {
			if locator = strings.TrimSpace(locator); locator == "" {
				continue
			}
			out.PackageExternalReferences = append(out.PackageExternalReferences, &v23.PackageExternalReference{
				Category:           term.category,
				RefType:            term.refType,
				Locator:            locator,
				ExternalRefComment: comment,
			})
		}
	}
	l.packages[pkg] = out
	return out
}

// describes lowers the document's subject to 2.3 DESCRIBES relationships.
//
// SPDX 3 names a document's subject as its root elements -- directly, or
// through an SBOM (or other collection) that is itself a root -- and also
// allows a describes relationship from the document or a collection; 2.3 has
// only the relationship. All three forms are read.
func (l *spdx3Lowering) describes(d *v30.Document) []*v23.Relationship {
	var described []v30.AnyElement
	seen := make(map[v30.AnyElement]struct{})
	add := func(element v30.AnyElement) {
		if _, ok := l.packages[element]; !ok {
			return
		}
		if _, dup := seen[element]; dup {
			return
		}
		seen[element] = struct{}{}
		described = append(described, element)
	}
	for _, root := range d.RootElements {
		if collection, ok := root.(v30.AnyElementCollection); ok && !isNilElement(collection) {
			for _, inner := range collection.GetRootElements() {
				add(inner)
			}
			continue
		}
		add(root)
	}
	for _, element := range d.Elements {
		rel, ok := element.(v30.AnyRelationship)
		if !ok || isNilElement(rel) || rel.GetType() != v30.RelationshipType_Describes {
			continue
		}
		from := rel.GetFrom()
		if _, isCollection := from.(v30.AnyElementCollection); !isCollection {
			continue
		}
		for _, to := range rel.GetTo() {
			add(to)
		}
	}
	out := make([]*v23.Relationship, 0, len(described))
	for _, element := range described {
		out = append(out, &v23.Relationship{
			RefA:         common.DocElementID{ElementRefID: common.ElementID("DOCUMENT")},
			RefB:         common.DocElementID{ElementRefID: l.elementID(element)},
			Relationship: common.TypeRelationshipDescribe,
		})
	}
	return out
}

// lowerRelationship lowers a dependency between packages to DEPENDS_ON.
//
// SPDX 3 states a dependency as dependsOn, hasOptionalDependency or
// hasProvidedDependency, optionally scoped to a lifecycle phase; From_v2_3
// produces exactly those from the 2.3 dependency family. The 2.3 reader
// treats every member of that family as the same edge and takes scope from
// Bomly's own carrier instead (ADR-0043 gives SPDX no scope default), so the
// distinction is not needed to read the edge and DEPENDS_ON states it.
func (l *spdx3Lowering) lowerRelationship(rel v30.AnyRelationship) []*v23.Relationship {
	switch rel.GetType() {
	case v30.RelationshipType_DependsOn,
		v30.RelationshipType_HasOptionalDependency,
		v30.RelationshipType_HasProvidedDependency:
	default:
		return nil
	}
	from := rel.GetFrom()
	if _, ok := l.packages[from]; !ok {
		return nil
	}
	var out []*v23.Relationship
	for _, to := range rel.GetTo() {
		if _, ok := l.packages[to]; !ok {
			continue
		}
		out = append(out, &v23.Relationship{
			RefA:         common.DocElementID{ElementRefID: l.elementID(from)},
			RefB:         common.DocElementID{ElementRefID: l.elementID(to)},
			Relationship: common.TypeRelationshipDependsOn,
		})
	}
	return out
}

// applyLicenses writes each package's declared and concluded licenses.
//
// SPDX 3 states them as hasDeclaredLicense and hasConcludedLicense
// relationships to license elements; 2.3 as two expression fields. A
// package with more than one relationship of a kind holds all of them, which
// is their conjunction -- the composition From_v2_3 splits apart when one
// 2.3 field is converted to several relationships.
func (l *spdx3Lowering) applyLicenses(elements v30.ElementList) {
	declared := make(map[*v23.Package][]string)
	concluded := make(map[*v23.Package][]string)
	for _, element := range elements {
		rel, ok := element.(v30.AnyRelationship)
		if !ok || isNilElement(rel) {
			continue
		}
		var target map[*v23.Package][]string
		switch rel.GetType() {
		case v30.RelationshipType_HasDeclaredLicense:
			target = declared
		case v30.RelationshipType_HasConcludedLicense:
			target = concluded
		default:
			continue
		}
		pkg, ok := l.packages[rel.GetFrom()]
		if !ok {
			continue
		}
		for _, to := range rel.GetTo() {
			license, ok := to.(v30.AnyLicenseInfo)
			if !ok {
				continue
			}
			if expression, ok := renderSPDX3License(license); ok {
				target[pkg] = append(target[pkg], expression)
			}
		}
	}
	for pkg, expressions := range declared {
		pkg.PackageLicenseDeclared = conjoinSPDXExpressions(expressions)
	}
	for pkg, expressions := range concluded {
		pkg.PackageLicenseConcluded = conjoinSPDXExpressions(expressions)
	}
}

// conjoinSPDXExpressions joins expressions with AND, parenthesizing each so
// precedence is preserved; NOASSERTION beside a real license says nothing and
// is left out.
func conjoinSPDXExpressions(expressions []string) string {
	kept := make([]string, 0, len(expressions))
	for _, expression := range expressions {
		if len(expressions) > 1 && isSPDXSentinel(expression) {
			continue
		}
		kept = append(kept, expression)
	}
	switch len(kept) {
	case 0:
		return ""
	case 1:
		return kept[0]
	}
	for i, expression := range kept {
		kept[i] = "(" + expression + ")"
	}
	return strings.Join(kept, " AND ")
}

// lowerSPDX3CustomLicense keeps a custom license's text, which 2.3 holds in
// the extracted-licensing section under the same reference. The library
// fills a missing text with NOASSERTION, which is not a text.
func lowerSPDX3CustomLicense(custom *v30.CustomLicense) *v23.OtherLicense {
	ref, ok := spdx3CustomIdentifier(custom.ID, "LicenseRef-")
	if !ok || !strings.HasPrefix(ref, "LicenseRef-") {
		return nil
	}
	text := strings.TrimSpace(custom.Text)
	if text == "" || isSPDXSentinel(text) {
		return nil
	}
	return &v23.OtherLicense{
		LicenseIdentifier: ref,
		ExtractedText:     custom.Text,
		LicenseName:       custom.Name,
		LicenseComment:    custom.Comment,
	}
}

func lowerSPDX3Checksums(methods v30.IntegrityMethodList) []common.Checksum {
	var out []common.Checksum
	for _, method := range methods {
		hash, ok := method.(*v30.Hash)
		if !ok || hash == nil || strings.TrimSpace(hash.Value) == "" {
			continue
		}
		algorithm, ok := spdx3ChecksumAlgorithm(hash.Algorithm)
		if !ok {
			continue
		}
		out = append(out, common.Checksum{Algorithm: algorithm, Value: strings.TrimSpace(hash.Value)})
	}
	return out
}

// lowerSPDX3Agent renders an agent as the 2.3 "Type: Name (email)" parts. A
// software agent is a 2.3 Tool; an agent of no more specific class has no 2.3
// type and is dropped, as 2.3 itself would not accept it.
func lowerSPDX3Agent(agent v30.AnyAgent) (kind, value string, ok bool) {
	if isNilElement(agent) {
		return "", "", false
	}
	switch agent.(type) {
	case *v30.Person:
		kind = "Person"
	case *v30.Organization:
		kind = "Organization"
	case *v30.SoftwareAgent:
		kind = spdxToolCreatorType
	default:
		return "", "", false
	}
	value = strings.TrimSpace(agent.GetName())
	if value == "" {
		return "", "", false
	}
	for _, identifier := range agent.GetExternalIdentifiers() {
		if identifier == nil {
			continue
		}
		if identifier.GetType() == v30.ExternalIdentifierType_Email && strings.TrimSpace(identifier.GetIdentifier()) != "" {
			value += " (" + strings.TrimSpace(identifier.GetIdentifier()) + ")"
			break
		}
	}
	return kind, value, true
}

func lowerSPDX3Supplier(agent v30.AnyAgent) *common.Supplier {
	kind, value, ok := lowerSPDX3Agent(agent)
	if !ok || kind == spdxToolCreatorType {
		return nil
	}
	return &common.Supplier{SupplierType: kind, Supplier: value}
}

func lowerSPDX3Originator(agent v30.AnyAgent) *common.Originator {
	kind, value, ok := lowerSPDX3Agent(agent)
	if !ok || kind == spdxToolCreatorType {
		return nil
	}
	return &common.Originator{OriginatorType: kind, Originator: value}
}

// lowerSPDX3CreationInfo lowers who and what created the document to 2.3
// creator lines. A tool appears both as a createdBy software agent and as a
// createdUsing tool in a document Bomly wrote; it is one creator.
func lowerSPDX3CreationInfo(info v30.AnyCreationInfo) *v23.CreationInfo {
	if isNilElement(info) {
		return nil
	}
	out := &v23.CreationInfo{CreatorComment: info.GetComment()}
	if created := info.GetCreated(); !created.IsZero() {
		out.Created = created.UTC().Format(time.RFC3339)
	}
	seen := make(map[string]struct{})
	add := func(kind, value string) {
		line := kind + ": " + value
		if _, dup := seen[line]; dup {
			return
		}
		seen[line] = struct{}{}
		out.Creators = append(out.Creators, common.Creator{CreatorType: kind, Creator: value})
	}
	for _, tool := range info.GetCreatedUsing() {
		if isNilElement(tool) {
			continue
		}
		if name := strings.TrimSpace(tool.GetName()); name != "" {
			add(spdxToolCreatorType, name)
		}
	}
	for _, agent := range info.GetCreatedBy() {
		if kind, value, ok := lowerSPDX3Agent(agent); ok {
			add(kind, value)
		}
	}
	return out
}

// lowerSPDX3Import lowers an imported document to a 2.3 external document
// reference, the form ADR-0042's source links take: the location is the
// source document's identity and the hash its checksum.
func lowerSPDX3Import(imported v30.AnyExternalMap) (v23.ExternalDocumentRef, bool) {
	if isNilElement(imported) {
		return v23.ExternalDocumentRef{}, false
	}
	uri := strings.TrimSpace(string(imported.GetLocationHint()))
	if uri == "" {
		uri = strings.TrimSpace(string(imported.GetExternalSpdxID()))
	}
	if uri == "" {
		return v23.ExternalDocumentRef{}, false
	}
	ref := v23.ExternalDocumentRef{
		DocumentRefID: common.DocumentID(strings.TrimPrefix(spdx3LocalName(string(imported.GetExternalSpdxID())), "DocumentRef-")),
		URI:           uri,
	}
	if checksums := lowerSPDX3Checksums(imported.GetVerifiedUsing()); len(checksums) > 0 {
		ref.Checksum = checksums[0]
	}
	return ref, true
}
