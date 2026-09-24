package sbom

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bomly-dev/bomly-sdk/spdxkit"

	"github.com/bomly-dev/bomly-sdk/model"
)

type cycloneDXCodec struct {
	version Target
}

func (c cycloneDXCodec) encodeJSON(doc *Document, opts EncodeOptions) ([]byte, error) {
	specVersion := toCycloneDXVersion(c.version)
	bom := cdx.NewBOM()
	bom.SerialNumber = doc.SerialNumber
	bom.Version = doc.SerialVersionOrDefault()

	components := make([]cdx.Component, 0, len(doc.Components))
	for _, comp := range doc.Components {
		if IsProjectRootComponent(comp) {
			// The synthesized project root lives in metadata.component (and
			// keeps its entry in the dependencies section); repeating it in
			// the component inventory would double-count it.
			continue
		}
		components = append(components, cycloneDXComponent(comp, specVersion))
	}
	bom.Components = &components

	if vulns := cycloneDXVulnerabilities(doc.Components); len(vulns) > 0 {
		bom.Vulnerabilities = &vulns
	}

	deps := make([]cdx.Dependency, 0, len(doc.Dependencies))
	for _, dep := range doc.Dependencies {
		cd := cdx.Dependency{Ref: dep.Ref}
		if len(dep.DependsOn) > 0 {
			children := make([]string, len(dep.DependsOn))
			copy(children, dep.DependsOn)
			cd.Dependencies = &children
		}
		deps = append(deps, cd)
	}
	bom.Dependencies = &deps

	metadata := &cdx.Metadata{
		Timestamp: doc.CreatedOrNow().Format(time.RFC3339),
		Tools:     cycloneDXMetadataTools(doc),
	}
	if root := chooseRoot(doc); root != nil {
		// The primary component is built the same way as an inventory entry.
		// A natural root appears in both places, and a reduced copy here would
		// describe the scanned project with less detail -- no licenses, hashes,
		// CPE, or origin -- than the same package carries a few lines below.
		primary := cycloneDXComponent(*root, specVersion)
		primary.Type = cycloneDXComponentType(firstNonEmpty(root.Type, "application"))
		if refs := cycloneDXSecurityReferences(doc.Provenance); len(refs) > 0 {
			merged := refs
			if primary.ExternalReferences != nil {
				merged = append(append([]cdx.ExternalReference(nil), *primary.ExternalReferences...), refs...)
			}
			primary.ExternalReferences = &merged
		}
		metadata.Component = &primary
	}
	metadata.Manufacturer = cycloneDXDocumentManufacturer(doc)
	if authors := cycloneDXDocumentAuthors(doc); len(authors) > 0 {
		metadata.Authors = &authors
	}
	if props := cycloneDXMetadataProperties(doc.Provenance); len(props) > 0 {
		metadata.Properties = &props
	}
	if phase := cycloneDXLifecyclePhase(doc.Lifecycle); phase != "" {
		metadata.Lifecycles = &[]cdx.Lifecycle{{Phase: phase}}
	}
	bom.Metadata = metadata

	if aggregate := cycloneDXAggregate(doc.Aggregate); aggregate != "" {
		bom.Compositions = &[]cdx.Composition{{Aggregate: aggregate}}
	}

	// The documents this one was built from, named rather than inherited.
	// Empty for a native scan and for a conversion that adopted its single
	// source's identity; populated for a merge, and for a conversion whose
	// source identity this format cannot hold.
	if links := cycloneDXSourceLinks(doc); len(links) > 0 {
		bom.ExternalReferences = &links
	}

	var out bytes.Buffer
	enc := cdx.NewBOMEncoder(&out, cdx.BOMFileFormatJSON).SetPretty(opts.Pretty)
	if err := enc.EncodeVersion(bom, specVersion); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func (c cycloneDXCodec) decodeJSON(data []byte) (*Document, error) {
	bom := new(cdx.BOM)
	dec := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON)
	if err := dec.Decode(bom); err != nil {
		return nil, err
	}

	// What a document can state is fixed by the version it declares, not by
	// the target a caller asked to read it as. The target stands in only when
	// the document names no version.
	specVersion := bom.SpecVersion
	if specVersion == 0 {
		specVersion = toCycloneDXVersion(c.version)
	}

	var inventory []cdx.Component
	if bom.Components != nil {
		inventory = *bom.Components
	}
	var primary *cdx.Component
	if bom.Metadata != nil {
		primary = bom.Metadata.Component
	}

	componentByID := make(map[string]Component)
	var unknownScopes []string
	refs := newCycloneDXRefAllocator(inventory, primary)
	inventoryIDs := make([]string, len(inventory))
	for index, comp := range inventory {
		unknownScopes = mergeUnknownScopeTokens(unknownScopes, unknownScopeTokens(cycloneDXCarriedScopes(comp.Properties)))
		component := decodeCycloneDXComponent(comp, refs.allocate(comp, index), specVersion)
		inventoryIDs[index] = component.ID
		componentByID[component.ID] = component
	}

	// metadata.component is, in the specification's words, "the component
	// that the BOM describes". A producer may list it in the inventory as
	// well, or only here; either way it is part of the document, and its
	// dependency entry is a real edge to what it depends on. Only Bomly's own
	// synthesized document root is not a package: it stands for "this scan"
	// when the graph had several roots, and reading it back would demote
	// those roots under a node nothing depends on. A document whose only
	// component is its primary one keeps that component whatever it is.
	primaryRef := ""
	var described []string
	if primary != nil {
		primaryRef = strings.TrimSpace(primary.BOMRef)
		listedID, listed := cycloneDXListedPrimary(*primary, inventory, inventoryIDs)
		switch {
		case listed:
			described = []string{listedID}
		case len(componentByID) == 0 || !isProjectRootID(primaryRef):
			unknownScopes = mergeUnknownScopeTokens(unknownScopes, unknownScopeTokens(cycloneDXCarriedScopes(primary.Properties)))
			component := decodeCycloneDXComponent(*primary, refs.allocate(*primary, len(inventory)), specVersion)
			componentByID[component.ID] = component
			described = []string{component.ID}
		}
	}
	distributeCycloneDXVulnerabilities(bom.Vulnerabilities, componentByID)

	dependencies := make([]Dependency, 0, len(componentByID))
	inDegree := make(map[string]int, len(componentByID))
	if bom.Dependencies != nil {
		for _, dep := range *bom.Dependencies {
			if _, known := componentByID[dep.Ref]; !known && (isProjectRootID(dep.Ref) || dep.Ref == primaryRef) {
				// Bomly's synthesized document root was not read as a
				// component above; its dependency entry links it to the real
				// graph roots and must not demote those roots on re-ingestion.
				continue
			}
			ds := make([]string, 0)
			if dep.Dependencies != nil {
				ds = append(ds, *dep.Dependencies...)
				for _, child := range ds {
					inDegree[child]++
				}
			}
			if len(ds) > 1 {
				sort.Strings(ds)
			}
			dependencies = append(dependencies, Dependency{
				Ref:       dep.Ref,
				DependsOn: ds,
			})
		}
	}

	components := make([]Component, 0, len(componentByID))
	for _, comp := range componentByID {
		components = append(components, comp)
	}
	sort.Slice(components, func(i, j int) bool { return components[i].ID < components[j].ID })

	if len(dependencies) == 0 {
		dependencies = make([]Dependency, 0, len(components))
		for _, comp := range components {
			dependencies = append(dependencies, Dependency{Ref: comp.ID})
		}
	}
	sort.Slice(dependencies, func(i, j int) bool { return dependencies[i].Ref < dependencies[j].Ref })

	roots := make([]string, 0)
	for _, comp := range components {
		if inDegree[comp.ID] == 0 {
			roots = append(roots, comp.ID)
		}
	}
	sort.Strings(roots)

	created := time.Time{}
	if bom.Metadata != nil && bom.Metadata.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339, bom.Metadata.Timestamp); err == nil {
			created = t.UTC()
		}
	}

	return &Document{
		Name:               defaultDocumentName,
		Assertions:         cycloneDXDocumentAssertions(bom),
		Tool:               cycloneDXPrimaryToolName(bom.Metadata),
		Tools:              cycloneDXToolNames(bom.Metadata),
		Created:            created,
		SerialNumber:       bom.SerialNumber,
		SerialVersion:      bom.Version,
		Lifecycle:          cycloneDXDecodedLifecycle(bom.Metadata),
		Aggregate:          cycloneDXDecodedAggregate(bom.Compositions),
		Components:         components,
		Dependencies:       dependencies,
		Roots:              roots,
		Described:          described,
		UnknownScopeTokens: unknownScopes,
	}, nil
}

// cycloneDXListedPrimary finds metadata.component in the inventory, returning
// the key that inventory entry was decoded under. A stated bom-ref is the
// match when there is one: it is the only handle the format gives. A
// primary component without one cannot be referenced at all, so it is the
// inventory entry that carries the same package URL, or, lacking one, the
// same name and version, or, lacking a version too, the one entry with that
// bare name; reading it as a second component would list one package twice.
// A bare name that several inventory entries share names none of them.
func cycloneDXListedPrimary(primary cdx.Component, inventory []cdx.Component, ids []string) (string, bool) {
	if ref := strings.TrimSpace(primary.BOMRef); ref != "" {
		for index, comp := range inventory {
			if strings.TrimSpace(comp.BOMRef) == ref {
				return ids[index], true
			}
		}
		return "", false
	}
	purl := strings.TrimSpace(primary.PackageURL)
	name, version := strings.TrimSpace(primary.Name), strings.TrimSpace(primary.Version)
	match, matches := "", 0
	for index, comp := range inventory {
		switch {
		case purl != "":
			if strings.TrimSpace(comp.PackageURL) == purl {
				return ids[index], true
			}
		case name != "":
			if strings.TrimSpace(comp.PackageURL) == "" && strings.TrimSpace(comp.Name) == name && strings.TrimSpace(comp.Version) == version {
				if version != "" {
					return ids[index], true
				}
				match = ids[index]
				matches++
			}
		}
	}
	return match, matches == 1
}

// distributeCycloneDXVulnerabilities reads a document's vulnerabilities back
// onto the components they affect -- the inverse of cycloneDXVulnerabilities,
// which gathers each component's vulnerabilities into one top-level entry
// with an affects list. Without it a direct round trip dropped every
// vulnerability, and an affected inventory re-exported clean.
//
// An affects reference that names no component of this document (a BOM-Link
// into another BOM, or a dangling ref) has nothing here to attach to and is
// not read. The intermediate model holds one rating per vulnerability, which
// is also all the encoder writes; the first rating the source listed is the
// one kept.
func distributeCycloneDXVulnerabilities(vulnerabilities *[]cdx.Vulnerability, componentByID map[string]Component) {
	if vulnerabilities == nil {
		return
	}
	for _, source := range *vulnerabilities {
		if strings.TrimSpace(source.ID) == "" || source.Affects == nil {
			continue
		}
		vuln := decodeCycloneDXVulnerability(source)
		attached := make(map[string]struct{}, len(*source.Affects))
		for _, affects := range *source.Affects {
			ref := strings.TrimSpace(affects.Ref)
			component, ok := componentByID[ref]
			if !ok {
				continue
			}
			if _, done := attached[ref]; done {
				continue
			}
			attached[ref] = struct{}{}
			component.Vulnerabilities = append(component.Vulnerabilities, vuln)
			componentByID[ref] = component
		}
	}
}

// decodeCycloneDXVulnerability reads the fields cycloneDXVulnerability
// writes.
func decodeCycloneDXVulnerability(source cdx.Vulnerability) Vulnerability {
	vuln := Vulnerability{
		ID:             source.ID,
		Description:    source.Description,
		Recommendation: source.Recommendation,
	}
	if source.Source != nil {
		vuln.Source = source.Source.Name
	}
	if source.Ratings != nil && len(*source.Ratings) > 0 {
		rating := (*source.Ratings)[0]
		vuln.Severity = string(rating.Severity)
		vuln.Vector = rating.Vector
		vuln.Method = string(rating.Method)
		if rating.Score != nil {
			vuln.Score = new(*rating.Score)
		}
		if vuln.Source == "" && rating.Source != nil {
			vuln.Source = rating.Source.Name
		}
	}
	if source.CWEs != nil && len(*source.CWEs) > 0 {
		vuln.CWEs = append([]int(nil), *source.CWEs...)
	}
	if source.Advisories != nil {
		for _, advisory := range *source.Advisories {
			if url := strings.TrimSpace(advisory.URL); url != "" {
				vuln.Advisories = append(vuln.Advisories, url)
			}
		}
	}
	vuln.Analysis = decodeCycloneDXAnalysis(source.Analysis)
	return vuln
}

// decodeCycloneDXAnalysis reads the VEX block through the model's gate, so a
// state or justification outside the specification's vocabulary is dropped
// here rather than carried as a word CycloneDX does not define.
func decodeCycloneDXAnalysis(source *cdx.VulnerabilityAnalysis) *model.VulnerabilityAnalysis {
	if source == nil {
		return nil
	}
	analysis := model.VulnerabilityAnalysis{
		State:         model.ImpactAnalysisState(source.State),
		Justification: model.ImpactAnalysisJustification(source.Justification),
		Detail:        source.Detail,
		FirstIssued:   source.FirstIssued,
		LastUpdated:   source.LastUpdated,
	}
	if source.Response != nil {
		for _, response := range *source.Response {
			analysis.Response = append(analysis.Response, model.ImpactAnalysisResponse(response))
		}
	}
	normalized, ok := analysis.Normalized()
	if !ok {
		return nil
	}
	return &normalized
}

// cycloneDXAnalysis writes the VEX block back in the library's shape; the
// value was gated on the way in and again wherever it was merged.
func cycloneDXAnalysis(analysis *model.VulnerabilityAnalysis) *cdx.VulnerabilityAnalysis {
	if analysis == nil {
		return nil
	}
	normalized, ok := analysis.Normalized()
	if !ok {
		return nil
	}
	out := &cdx.VulnerabilityAnalysis{
		State:         cdx.ImpactAnalysisState(normalized.State),
		Justification: cdx.ImpactAnalysisJustification(normalized.Justification),
		Detail:        normalized.Detail,
		FirstIssued:   normalized.FirstIssued,
		LastUpdated:   normalized.LastUpdated,
	}
	if len(normalized.Response) > 0 {
		responses := make([]cdx.ImpactAnalysisResponse, 0, len(normalized.Response))
		for _, response := range normalized.Response {
			responses = append(responses, cdx.ImpactAnalysisResponse(response))
		}
		out.Response = &responses
	}
	return out
}

// decodeCycloneDXComponent reads one component, from the inventory or from
// metadata.component, with every assertion the format carries. Both places
// read the same fields: reading the primary component with half of them was a
// silent hole, where supplier, description, hashes, CPE and references all
// stopped.
func decodeCycloneDXComponent(comp cdx.Component, id string, specVersion cdx.SpecVersion) Component {
	component := Component{
		ID:     id,
		Name:   comp.Name,
		Org:    comp.Group,
		Type:   string(comp.Type),
		Scopes: model.ScopesFromCycloneDXComponent(string(comp.Scope), cycloneDXCarriedScopes(comp.Properties)),
		// The word beside the set it derives, so an export can say what this
		// document said rather than Bomly's projection of it. Gated by the
		// SDK, which is also what refuses a value that is not a scope word at
		// all.
		SourceScope: model.NormalizeSourceScope(string(comp.Scope)),
		Version:     comp.Version,
		PURL:        comp.PackageURL,
		Copyright:   model.NormalizeCopyright(comp.Copyright),
		Licenses:    parseCycloneDXLicenses(comp.Licenses, specVersion),
	}
	applyCycloneDXAssertions(&component, comp)
	return component
}

// cycloneDXSecurityReferences maps provenance contact fields onto external
// references attached to the primary component.
// cycloneDXComponentReferences renders where a package came from: the exact
// file it was fetched from as a distribution reference, or the repository it
// was resolved from as a vcs reference. The repository is rendered as a plain
// URL -- CycloneDX external references carry no revision, so the commit a
// detector resolved is only expressible in the SPDX locator form.
func cycloneDXComponentReferences(component Component) []cdx.ExternalReference {
	origins := component.Origins
	if len(origins) == 0 {
		// A component whose URLs came from registry enrichment rather than a
		// detector-asserted origin still has the single-valued fields.
		origins = []ComponentOrigin{{
			ArtifactURL: component.ArtifactURL,
			Repository:  component.VCSURL,
			Revision:    component.VCSRevision,
		}}
	}
	refs := make([]cdx.ExternalReference, 0, 2*len(origins))
	seen := make(map[cdx.ExternalReference]struct{}, 2*len(origins))
	add := func(ref cdx.ExternalReference) {
		if strings.TrimSpace(ref.URL) == "" {
			return
		}
		if _, duplicate := seen[ref]; duplicate {
			return
		}
		seen[ref] = struct{}{}
		refs = append(refs, ref)
	}
	// Every origin, not just the first: CycloneDX allows an external
	// reference list, so two registries a package resolved from are both
	// expressible and both stay.
	for _, origin := range origins {
		add(cdx.ExternalReference{Type: cdx.ERTypeDistribution, URL: strings.TrimSpace(origin.ArtifactURL)})
		add(cdx.ExternalReference{Type: cdx.ERTypeVCS, URL: strings.TrimSpace(origin.Repository)})
	}
	// Enrichment may have filled the repository when no origin asserted one.
	add(cdx.ExternalReference{Type: cdx.ERTypeVCS, URL: strings.TrimSpace(component.VCSURL)})
	return refs
}

func cycloneDXSecurityReferences(p Provenance) []cdx.ExternalReference {
	refs := make([]cdx.ExternalReference, 0, 2)
	if contact := strings.TrimSpace(p.SecurityContact); contact != "" {
		if !strings.Contains(contact, ":") && strings.Contains(contact, "@") {
			contact = "mailto:" + contact
		}
		refs = append(refs, cdx.ExternalReference{Type: cdx.ERTypeSecurityContact, URL: contact})
	}
	if disclosure := strings.TrimSpace(p.VulnerabilityDisclosureURL); disclosure != "" {
		refs = append(refs, cdx.ExternalReference{Type: cdx.ERTypeAdvisories, URL: disclosure, Comment: "Coordinated vulnerability disclosure policy"})
	}
	if len(refs) == 0 {
		return nil
	}
	return refs
}

// bareEmail returns value when it looks like a plain email address (no URI
// scheme), otherwise "".
func bareEmail(value string) string {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "@") && !strings.Contains(value, ":") && !strings.Contains(value, "/") {
		return value
	}
	return ""
}

// cycloneDXLifecyclePhase validates a lifecycle phase against the CycloneDX
// vocabulary, returning "" for unknown values so an invalid phase can never
// make the document non-conformant.
func cycloneDXLifecyclePhase(value string) cdx.LifecyclePhase {
	switch cdx.LifecyclePhase(strings.ToLower(strings.TrimSpace(value))) {
	case cdx.LifecyclePhaseDesign, cdx.LifecyclePhasePreBuild, cdx.LifecyclePhaseBuild,
		cdx.LifecyclePhasePostBuild, cdx.LifecyclePhaseOperations, cdx.LifecyclePhaseDiscovery,
		cdx.LifecyclePhaseDecommission:
		return cdx.LifecyclePhase(strings.ToLower(strings.TrimSpace(value)))
	default:
		return ""
	}
}

// cycloneDXAggregate validates a composition aggregate value, returning "" for
// unknown values.
func cycloneDXAggregate(value string) cdx.CompositionAggregate {
	switch cdx.CompositionAggregate(strings.ToLower(strings.TrimSpace(value))) {
	case cdx.CompositionAggregateComplete, cdx.CompositionAggregateIncomplete,
		cdx.CompositionAggregateIncompleteFirstPartyOnly, cdx.CompositionAggregateIncompleteFirstPartyOpenSourceOnly,
		cdx.CompositionAggregateIncompleteThirdPartyOnly, cdx.CompositionAggregateIncompleteThirdPartyOpenSourceOnly,
		cdx.CompositionAggregateNotSpecified, cdx.CompositionAggregateUnknown:
		return cdx.CompositionAggregate(strings.ToLower(strings.TrimSpace(value)))
	default:
		return ""
	}
}

// cycloneDXDecodedLifecycle reads back the lifecycle phase the encoder writes.
// Document holds one phase, so it is read only when the document states
// exactly one pre-defined phase: choosing one of several would drop the rest
// while claiming to restate them, and a custom lifecycle (name and
// description) has no phase to hold.
func cycloneDXDecodedLifecycle(metadata *cdx.Metadata) string {
	if metadata == nil || metadata.Lifecycles == nil || len(*metadata.Lifecycles) != 1 {
		return ""
	}
	return string(cycloneDXLifecyclePhase(string((*metadata.Lifecycles)[0].Phase)))
}

// cycloneDXDecodedAggregate reads back the completeness declaration the
// encoder writes: one composition scoped to nothing, which is a claim about
// the whole document. A composition that lists assemblies, dependencies or
// vulnerabilities speaks only for those, so it is not a document-wide claim
// and is not read as one; neither is a document with several compositions.
func cycloneDXDecodedAggregate(compositions *[]cdx.Composition) string {
	if compositions == nil || len(*compositions) != 1 {
		return ""
	}
	composition := (*compositions)[0]
	if composition.Assemblies != nil || composition.Dependencies != nil || composition.Vulnerabilities != nil {
		return ""
	}
	return string(cycloneDXAggregate(string(composition.Aggregate)))
}

func cycloneDXMetadataProperties(p Provenance) []cdx.Property {
	if strings.TrimSpace(p.SupportEnd) == "" {
		return nil
	}
	return []cdx.Property{{Name: "bomly:support_end_date", Value: strings.TrimSpace(p.SupportEnd)}}
}

func cycloneDXToolNames(metadata *cdx.Metadata) []string {
	if metadata == nil || metadata.Tools == nil {
		return nil
	}
	names := make([]string, 0)
	if metadata.Tools.Components != nil {
		for _, tool := range *metadata.Tools.Components {
			if strings.TrimSpace(tool.Name) != "" {
				names = append(names, tool.Name)
			}
		}
	}
	if metadata.Tools.Tools != nil {
		for _, tool := range *metadata.Tools.Tools {
			if strings.TrimSpace(tool.Name) != "" {
				names = append(names, tool.Name)
			}
		}
	}
	return names
}

func cycloneDXPrimaryToolName(metadata *cdx.Metadata) string {
	names := cycloneDXToolNames(metadata)
	if len(names) > 0 {
		return names[0]
	}
	return defaultToolName
}

// cycloneDXComponentType maps a component type onto CycloneDX's vocabulary.
// Every type cyclonedx-go defines is kept as itself, so a type a document
// stated survives a round trip; anything else -- Bomly's own "package", a
// domain type such as a workflow -- is a library. The vocabulary grew across
// specification versions (device-driver, platform, data and
// machine-learning-model arrived in 1.5, cryptographic-asset in 1.6), and
// writing an older version is cyclonedx-go's job: EncodeVersion rewrites a type
// that version does not define.
func cycloneDXComponentType(value string) cdx.ComponentType {
	switch componentType := cdx.ComponentType(strings.ToLower(strings.TrimSpace(value))); componentType {
	case cdx.ComponentTypeApplication,
		cdx.ComponentTypeContainer,
		cdx.ComponentTypeCryptographicAsset,
		cdx.ComponentTypeData,
		cdx.ComponentTypeDevice,
		cdx.ComponentTypeDeviceDriver,
		cdx.ComponentTypeFile,
		cdx.ComponentTypeFirmware,
		cdx.ComponentTypeFramework,
		cdx.ComponentTypeLibrary,
		cdx.ComponentTypeMachineLearningModel,
		cdx.ComponentTypeOS,
		cdx.ComponentTypePlatform:
		return componentType
	default:
		return cdx.ComponentTypeLibrary
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// cycloneDXScopeProperty carries the full scope set beside CycloneDX's scalar
// scope, so the projection is not a one-way door.
func cycloneDXScopeProperty(scopes []model.Scope) (cdx.Property, bool) {
	value := model.EncodeScopeSet(scopes)
	if value == "" {
		return cdx.Property{}, false
	}
	return cdx.Property{Name: model.CycloneDXScopeProperty, Value: value}, true
}

// cycloneDXCarriedScopes reads the carrier property back off a component.
func cycloneDXCarriedScopes(properties *[]cdx.Property) string {
	if properties == nil {
		return ""
	}
	for _, property := range *properties {
		if property.Name == model.CycloneDXScopeProperty {
			return property.Value
		}
	}
	return ""
}

// chooseRoot is the component metadata.component names: "the component that
// the BOM describes", in the specification's words, and optional. A decoded
// document keeps the subject its source named, even when the graph also has a
// disconnected root the source never called its subject. Otherwise only a
// document with exactly one root has a subject of its own -- a natural single
// root, or the project root a projection synthesized for a graph that had
// several. With several roots and no synthesized one, or none at all (every
// component inside a cycle), no component is the subject, and picking the
// first one published a claim that the BOM describes an arbitrary dependency.
func chooseRoot(doc *Document) *Component {
	if doc == nil {
		return nil
	}
	described := doc.describedIDs()
	if len(described) != 1 {
		return nil
	}
	for i := range doc.Components {
		if doc.Components[i].ID == described[0] {
			return &doc.Components[i]
		}
	}
	return nil
}

func toCycloneDXVersion(target Target) cdx.SpecVersion {
	switch target {
	case TargetCycloneDX14JSON:
		return cdx.SpecVersion1_4
	case TargetCycloneDX15JSON:
		return cdx.SpecVersion1_5
	case TargetCycloneDX16JSON:
		return cdx.SpecVersion1_6
	default:
		return cdx.SpecVersion1_7
	}
}

// cycloneDXComponent renders one intermediate component into its CycloneDX
// form. Both the component inventory and metadata.component go through it, so
// the document describes a package the same way wherever it appears.
func cycloneDXComponent(comp Component, specVersion cdx.SpecVersion) cdx.Component {
	component := cdx.Component{
		BOMRef: comp.ID,
		Type:   cycloneDXComponentType(comp.Type),
		Name:   comp.NameOrID(),
		Group:  comp.Org,
		// The source document's own word when Bomly's scope set still means
		// what that word meant, and the projection of the set otherwise. The
		// SDK owns that decision: it is the same mapping that read the word
		// in, and only it can say whether the word still describes the set
		// (ADR-0037).
		Scope:      cdx.Scope(model.CycloneDXScopeForExport(comp.Scopes, comp.SourceScope)),
		Version:    comp.Version,
		PackageURL: comp.PURL,
		Copyright:  model.NormalizeCopyright(comp.Copyright),
	}
	if licenses := cycloneDXLicenses(comp.Licenses, specVersion); len(licenses) > 0 {
		component.Licenses = &licenses
	}
	if len(comp.CPEs) > 0 {
		component.CPE = comp.CPEs[0]
	}
	if hashes := cycloneDXHashes(comp.Digests); len(hashes) > 0 {
		component.Hashes = &hashes
	}
	props := cycloneDXEOLProperties(comp.EOL)
	if scopeProperty, ok := cycloneDXScopeProperty(comp.Scopes); ok {
		props = append(props, scopeProperty)
	}
	if len(props) > 0 {
		sort.Slice(props, func(i, j int) bool { return props[i].Name < props[j].Name })
		component.Properties = &props
	}
	// Origin-derived references first, then the ones the source document
	// asserted. Both are references about the same component and the format
	// carries one list, so they concatenate; the emitted set is deduplicated
	// by the SDK's reference identity before it is written.
	refs := cycloneDXComponentReferences(comp)
	refs = append(refs, cycloneDXEmittedReferences(cycloneDXComponentAssertedReferences(comp))...)
	if len(refs) > 0 {
		component.ExternalReferences = &refs
	}
	component.Supplier = cycloneDXEntityFor(comp.Supplier)
	cycloneDXApplyOriginator(&component, comp.Originator)
	component.Description = model.NormalizeDescription(comp.Description)
	return component
}

// cycloneDXComponentAssertedReferences returns the references a source
// document asserted about a component, plus the website reference its homepage
// is carried in.
func cycloneDXComponentAssertedReferences(comp Component) []model.ExternalReference {
	refs := comp.ExternalReferences
	if homepage, ok := cycloneDXHomepageReference(comp); ok {
		refs = model.MergeExternalReferences(refs, []model.ExternalReference{homepage})
	}
	return refs
}

// cycloneDXLicenses renders a component's licenses into CycloneDX, each claim
// marked with the kind of claim it is.
//
// CycloneDX 1.6 added acknowledgement for the distinction the model's
// LicenseType draws: a declared license is what the package's authors
// intended, a concluded one what an analysis confirmed (the schema's
// licenseAcknowledgementEnumeration). The field is optional, so a claim with
// no type carries none -- absence is the document not saying, and writing
// "declared" would state a provenance no source gave. A set with no typed
// claim therefore renders exactly as it did before the field existed.
//
// Typed claims are rendered one kind at a time by cycloneDXLicenseChoices and
// then listed together, which the specification version constrains:
//
//   - 1.7 lets a license list mix objects and expressions, each with its own
//     acknowledgement, so the kinds are always kept apart.
//   - 1.4 to 1.6 allow a list of license objects or exactly one expression.
//     When the kinds together fit that shape they are kept apart; when they do
//     not -- an expression beside anything else -- no typed rendering is
//     valid, and the set falls back to the untyped one. That keeps every
//     license and asserts no provenance, rather than dropping a claim or
//     labelling an expression that mixes both kinds.
//   - Before 1.6 no schema defines acknowledgement, so none is written.
//     Downgrading is normally EncodeVersion's job, but cyclonedx-go v0.12.0's
//     convertLicenses clears only the license-object form and leaves the
//     expression form's acknowledgement in place, which a 1.4 or 1.5
//     consumer would reject. The version is checked here instead.
func cycloneDXLicenses(licenses []License, specVersion cdx.SpecVersion) cdx.Licenses {
	groups := licenseGroupsByType(licenses)
	if len(groups) == 0 {
		return nil
	}
	if specVersion < cdx.SpecVersion1_6 || (len(groups) == 1 && groups[0].acknowledgement == "") {
		return cycloneDXLicenseChoices(componentLicenseValues(licenses))
	}
	var out cdx.Licenses
	for _, group := range groups {
		choices := cycloneDXLicenseChoices(componentLicenseValues(group.licenses))
		if group.acknowledgement != "" {
			for i := range choices {
				setCycloneDXAcknowledgement(&choices[i], group.acknowledgement)
			}
		}
		out = append(out, choices...)
	}
	if specVersion < cdx.SpecVersion1_7 && !singleShapeLicenseChoices(out) {
		return cycloneDXLicenseChoices(componentLicenseValues(licenses))
	}
	return out
}

// licenseGroup is one kind of claim and the licenses that make it, in the
// order they first appeared.
type licenseGroup struct {
	acknowledgement cdx.LicenseAcknowledgement
	licenses        []License
}

// licenseGroupsByType splits licenses by the acknowledgement their type maps
// to, keeping first-appearance order so output is stable. Untyped claims, and
// claims whose type the model's gate does not recognize, share the group with
// no acknowledgement.
func licenseGroupsByType(licenses []License) []licenseGroup {
	var groups []licenseGroup
	index := make(map[cdx.LicenseAcknowledgement]int, 3)
	for _, license := range licenses {
		if licenseExpressionValue(license) == "" {
			continue
		}
		acknowledgement, _ := cycloneDXAcknowledgement(license.Type)
		at, ok := index[acknowledgement]
		if !ok {
			at = len(groups)
			index[acknowledgement] = at
			groups = append(groups, licenseGroup{acknowledgement: acknowledgement})
		}
		groups[at].licenses = append(groups[at].licenses, license)
	}
	return groups
}

// setCycloneDXAcknowledgement marks a rendered choice. The two shapes carry
// the field in different places: a license object on the object, an
// expression on the choice itself.
func setCycloneDXAcknowledgement(choice *cdx.LicenseChoice, acknowledgement cdx.LicenseAcknowledgement) {
	if choice.License != nil {
		choice.License.Acknowledgement = acknowledgement
		return
	}
	if choice.Expression != "" {
		choice.Acknowledgement = &acknowledgement
	}
}

// singleShapeLicenseChoices reports whether choices fit the license list that
// CycloneDX 1.4 to 1.6 define: all license objects, or exactly one expression.
func singleShapeLicenseChoices(choices cdx.Licenses) bool {
	if len(choices) == 1 {
		return true
	}
	for _, choice := range choices {
		if choice.License == nil {
			return false
		}
	}
	return true
}

// cycloneDXAcknowledgement maps a license type onto CycloneDX's vocabulary,
// through the model's gate so an unrecognized type is no type. Both sides are
// the owning packages' constants; neither spelling is written here.
func cycloneDXAcknowledgement(licenseType string) (cdx.LicenseAcknowledgement, bool) {
	parsed, err := model.ParseLicenseType(licenseType)
	if err != nil {
		return "", false
	}
	switch parsed {
	case model.LicenseTypeDeclared:
		return cdx.LicenseAcknowledgementDeclared, true
	case model.LicenseTypeConcluded:
		return cdx.LicenseAcknowledgementConcluded, true
	default:
		return "", false
	}
}

// licenseTypeFromCycloneDX maps an acknowledgement back onto the model's
// vocabulary. A value the specification does not define yields no type rather
// than a guess, as the model's own gate does for a provenance it does not
// recognize.
func licenseTypeFromCycloneDX(acknowledgement cdx.LicenseAcknowledgement) string {
	switch acknowledgement {
	case cdx.LicenseAcknowledgementDeclared:
		return string(model.LicenseTypeDeclared)
	case cdx.LicenseAcknowledgementConcluded:
		return string(model.LicenseTypeConcluded)
	default:
		return ""
	}
}

// cycloneDXLicenseChoices renders one set of license values into CycloneDX,
// without regard to what kind of claim they are.
//
// The format offers three shapes and scores them differently: `license.id` is
// a checked SPDX list entry, `expression` is a checked SPDX expression, and
// `license.name` is free text a consumer cannot reason about. Sources hand us
// all three kinds in the same field -- deps.dev records "non-standard" where
// it records "MIT" -- so the shape is chosen by validating the value, not by
// trusting its origin.
//
// Several licenses on one component carry no stated relationship: a source
// reports the licenses it found, not whether they apply together or offer a
// choice. CycloneDX can say exactly that -- a list of license entries asserts
// nothing about how they combine -- so a multi-license component is listed
// rather than composed, and "MIT AND Apache-2.0" is never claimed of a package
// that may be offered under either.
//
// A source that does know the relationship states it in one value
// ("Apache-2.0 OR MIT", which is how registries record dual licensing); that
// arrives as a single expression and passes through untouched.
//
// The one case that must compose is a list where some member is itself
// compound. A CycloneDX license list holds objects or one expression, never a
// mix, and an object cannot carry an expression -- so listing would degrade a
// real expression to free text. Composing keeps it, at the cost of asserting
// AND across the members.
func cycloneDXLicenseChoices(values []string) cdx.Licenses {
	if len(values) == 0 {
		return nil
	}

	if len(values) == 1 {
		value := values[0]
		if id, ok := spdxkit.Identifier(value); ok {
			return cdx.Licenses{{License: &cdx.License{ID: id}}}
		}
		if spdxkit.Valid(value) {
			// A compound expression has no license-object form; it can only be
			// carried as an expression.
			return cdx.Licenses{{Expression: value}}
		}
		return cdx.Licenses{{License: &cdx.License{Name: value}}}
	}

	if hasCompoundExpression(values) && allValidSPDXExpressions(values) {
		return cdx.Licenses{{Expression: spdxkit.Compose(values)}}
	}

	out := make(cdx.Licenses, 0, len(values))
	for _, value := range values {
		if id, ok := spdxkit.Identifier(value); ok {
			out = append(out, cdx.LicenseChoice{License: &cdx.License{ID: id}})
			continue
		}
		out = append(out, cdx.LicenseChoice{License: &cdx.License{Name: value}})
	}
	return out
}

// hasCompoundExpression reports whether any value is an expression rather than
// a bare license identifier, and so cannot survive as a license object.
func hasCompoundExpression(values []string) bool {
	for _, value := range values {
		if _, isID := spdxkit.Identifier(value); !isID && spdxkit.Valid(value) {
			return true
		}
	}
	return false
}

// cycloneDXHashes maps component digests onto CycloneDX hashes, dropping
// entries whose algorithm CycloneDX has no member for -- SHA224, MD2, MD4,
// MD6, and ADLER32 are SPDX-only, and an SBOM ingested from SPDX can carry
// them. publishableDigest is the gate; cycloneDXHashAlgorithm renders.
func cycloneDXHashes(digests []Digest) []cdx.Hash {
	if len(digests) == 0 {
		return nil
	}
	out := make([]cdx.Hash, 0, len(digests))
	for _, d := range digests {
		algorithm, value, ok := publishableDigest(d)
		if !ok {
			continue
		}
		spelling := cycloneDXHashAlgorithm(string(algorithm))
		if spelling == "" {
			continue
		}
		out = append(out, cdx.Hash{Algorithm: spelling, Value: value})
	}
	return out
}

// cycloneDXHashAlgorithm renders a digest algorithm in CycloneDX's spelling.
//
// The registry is the SDK's, not a list here. A hand-written switch stood in
// this spot and knew eight algorithms against the registry's nineteen, so a
// component carrying BLAKE2b, BLAKE3 or Streebog had that checksum silently
// dropped -- the same defect this PR already fixed on the SPDX side, in the
// same shape, one file away.
//
// An algorithm CycloneDX does not define returns "", which the caller drops.
// That is a real limit of the format: MD2, MD4, MD6 and ADLER32 are SPDX
// spellings with no CycloneDX equivalent.
func cycloneDXHashAlgorithm(algorithm string) cdx.HashAlgorithm {
	parsed, err := model.ParseDigestAlgorithm(algorithm)
	if err != nil {
		return ""
	}
	return cdx.HashAlgorithm(parsed.CycloneDXName())
}

// The property names carrying end-of-life through a CycloneDX document. They
// are named once because they are read as well as written, and a document
// whose reader and writer disagree about a name carries a field nobody can
// retrieve -- which is precisely what these did until now.
const (
	cycloneDXEOLProperty      = "bomly:eol"
	cycloneDXEOLDateProperty  = "bomly:eol_date"
	cycloneDXEOLCycleProperty = "bomly:eol_cycle"
)

func cycloneDXEOLProperties(eol *EOL) []cdx.Property {
	if eol == nil {
		return nil
	}
	props := make([]cdx.Property, 0, 3)
	props = append(props, cdx.Property{Name: cycloneDXEOLProperty, Value: strconv.FormatBool(eol.EOL)})
	if eol.EOLDate != "" {
		props = append(props, cdx.Property{Name: cycloneDXEOLDateProperty, Value: eol.EOLDate})
	}
	if eol.Cycle != "" {
		props = append(props, cdx.Property{Name: cycloneDXEOLCycleProperty, Value: eol.Cycle})
	}
	return props
}

// cycloneDXIngestedEOL reads the end-of-life claim back off a component.
//
// The flag is what makes the record exist: a date or a cycle without it says
// nothing about whether the version is end-of-life, and inventing false would
// assert something the document did not. An unparseable flag drops the record
// rather than guessing, on the same principle.
func cycloneDXIngestedEOL(properties *[]cdx.Property) *EOL {
	if properties == nil {
		return nil
	}
	var (
		eol    EOL
		stated bool
	)
	for _, property := range *properties {
		switch property.Name {
		case cycloneDXEOLProperty:
			flag, err := strconv.ParseBool(strings.TrimSpace(property.Value))
			if err != nil {
				return nil
			}
			eol.EOL = flag
			stated = true
		case cycloneDXEOLDateProperty:
			eol.EOLDate = strings.TrimSpace(property.Value)
		case cycloneDXEOLCycleProperty:
			eol.Cycle = strings.TrimSpace(property.Value)
		}
	}
	if !stated {
		return nil
	}
	return &eol
}

// cycloneDXVulnerabilities flattens per-component vulnerabilities into the
// BOM-level vulnerabilities array, deduplicating by advisory ID and collecting
// every affected component BOMRef under Affects.
func cycloneDXVulnerabilities(components []Component) []cdx.Vulnerability {
	type accumulator struct {
		vuln  Vulnerability
		refs  []string
		order int
	}
	byID := make(map[string]*accumulator)
	order := 0
	for _, comp := range components {
		for _, v := range comp.Vulnerabilities {
			if strings.TrimSpace(v.ID) == "" {
				continue
			}
			acc, ok := byID[v.ID]
			if !ok {
				acc = &accumulator{vuln: v, order: order}
				order++
				byID[v.ID] = acc
			} else if v.Analysis != nil {
				// One BOM-level advisory carries one analysis block, so the
				// per-component copies fold: the first component's words
				// stand and a later one fills only what the first left
				// empty, responses unioning. The rest of the record keeps
				// the first copy, as it always has.
				acc.vuln.Analysis = model.MergeVulnerabilityAnalysis(acc.vuln.Analysis, v.Analysis)
			}
			acc.refs = append(acc.refs, comp.ID)
		}
	}
	if len(byID) == 0 {
		return nil
	}
	out := make([]cdx.Vulnerability, 0, len(byID))
	for _, acc := range byID {
		out = append(out, cycloneDXVulnerability(acc.vuln, acc.refs))
	}
	sort.Slice(out, func(i, j int) bool {
		return byID[out[i].ID].order < byID[out[j].ID].order
	})
	return out
}

func cycloneDXVulnerability(v Vulnerability, refs []string) cdx.Vulnerability {
	vuln := cdx.Vulnerability{
		ID:             v.ID,
		Description:    v.Description,
		Recommendation: v.Recommendation,
	}
	if v.Source != "" {
		vuln.Source = &cdx.Source{Name: v.Source}
	}
	if v.Score != nil || v.Severity != "" || v.Vector != "" {
		rating := cdx.VulnerabilityRating{
			Severity: cycloneDXSeverity(v.Severity),
			Method:   cdx.ScoringMethod(v.Method),
			Vector:   v.Vector,
		}
		if v.Score != nil {
			rating.Score = new(*v.Score)
		}
		if v.Source != "" {
			rating.Source = &cdx.Source{Name: v.Source}
		}
		ratings := []cdx.VulnerabilityRating{rating}
		vuln.Ratings = &ratings
	}
	if len(v.CWEs) > 0 {
		vuln.CWEs = new(append([]int(nil), v.CWEs...))
	}
	if len(v.Advisories) > 0 {
		advisories := make([]cdx.Advisory, 0, len(v.Advisories))
		for _, url := range v.Advisories {
			advisories = append(advisories, cdx.Advisory{URL: url})
		}
		vuln.Advisories = &advisories
	}
	vuln.Analysis = cycloneDXAnalysis(v.Analysis)
	if len(refs) > 0 {
		sorted := append([]string(nil), refs...)
		sort.Strings(sorted)
		affects := make([]cdx.Affects, 0, len(sorted))
		for _, ref := range sorted {
			affects = append(affects, cdx.Affects{Ref: ref})
		}
		vuln.Affects = &affects
	}
	return vuln
}

func cycloneDXSeverity(severity string) cdx.Severity {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return cdx.SeverityCritical
	case "high":
		return cdx.SeverityHigh
	case "medium", "moderate":
		return cdx.SeverityMedium
	case "low":
		return cdx.SeverityLow
	case "none":
		return cdx.SeverityNone
	case "info", "informational":
		return cdx.SeverityInfo
	default:
		return cdx.SeverityUnknown
	}
}

// parseCycloneDXLicenses reads a component's licenses, with the kind of claim
// each one states.
//
// Each shape's acknowledgement is read from where the specification puts it:
// on the license object for the object form, on the choice for the
// expression form. A document that put it somewhere else did not state it,
// and reading the other place as a fallback would credit it with a claim it
// never made. Observed licenses (evidence.licenses) and a BOM's own
// metadata.licenses are not claims about the component and are not read here.
//
// The same holds across versions: acknowledgement arrived in 1.6, and a 1.4
// or 1.5 document that carries it anyway has stated nothing its schema
// defines. The decoder is lenient enough to fill the field regardless, so the
// document's version is checked here and the value is ignored below 1.6.
func parseCycloneDXLicenses(licenses *cdx.Licenses, specVersion cdx.SpecVersion) []License {
	if licenses == nil || len(*licenses) == 0 {
		return nil
	}
	acknowledged := specVersion >= cdx.SpecVersion1_6
	out := make([]License, 0, len(*licenses))
	for _, choice := range *licenses {
		switch {
		case choice.Expression != "":
			license := License{SPDXExpression: choice.Expression, Value: choice.Expression}
			if acknowledged && choice.Acknowledgement != nil {
				license.Type = licenseTypeFromCycloneDX(*choice.Acknowledgement)
			}
			out = append(out, license)
		case choice.License != nil:
			value := choice.License.ID
			if value == "" {
				value = choice.License.Name
			}
			license := License{Value: value, SPDXExpression: choice.License.ID}
			if acknowledged {
				license.Type = licenseTypeFromCycloneDX(choice.License.Acknowledgement)
			}
			out = append(out, license)
		}
	}
	return out
}

// cycloneDXRefAllocator hands out the key each decoded component is held
// under. It is the component's own bom-ref when it has one. CycloneDX makes
// bom-ref optional, and keying every ref-less component on "" folded them into
// one entry, so a third-party document with two such components lost
// inventory on ingest. A ref-less component is keyed on its package URL, then
// on name@version, then on its position, and a key already in use is suffixed
// with the position, counting up until the key is free -- the reference is a
// document-local handle and only has to be distinct; identity is minted from
// the coordinates when the document becomes a graph.
//
// Every stated bom-ref is reserved before any key is derived. The dependency
// graph names components by their stated refs, so a derived key must never
// take one, whichever of the two components comes first in the document.
type cycloneDXRefAllocator struct {
	used map[string]struct{}
}

func newCycloneDXRefAllocator(inventory []cdx.Component, primary *cdx.Component) *cycloneDXRefAllocator {
	used := make(map[string]struct{}, len(inventory)+1)
	reserve := func(comp cdx.Component) {
		if ref := strings.TrimSpace(comp.BOMRef); ref != "" {
			used[ref] = struct{}{}
		}
	}
	for _, comp := range inventory {
		reserve(comp)
	}
	if primary != nil {
		reserve(*primary)
	}
	return &cycloneDXRefAllocator{used: used}
}

func (a *cycloneDXRefAllocator) allocate(comp cdx.Component, index int) string {
	if ref := strings.TrimSpace(comp.BOMRef); ref != "" {
		a.used[ref] = struct{}{}
		return ref
	}
	base := strings.TrimSpace(comp.PackageURL)
	if base == "" {
		base = strings.TrimSpace(comp.Name)
		if version := strings.TrimSpace(comp.Version); base != "" && version != "" {
			base += "@" + version
		}
	}
	if base == "" {
		base = fmt.Sprintf("component-%d", index)
	}
	candidate := base
	for suffix := index; ; suffix++ {
		if _, clash := a.used[candidate]; !clash {
			break
		}
		candidate = fmt.Sprintf("%s-%d", base, suffix)
	}
	a.used[candidate] = struct{}{}
	return candidate
}
