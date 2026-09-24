package sbom

import (
	"fmt"
	"sort"
	"strings"

	spdxcommon "github.com/spdx/tools-golang/spdx/v2/common"

	"github.com/bomly-dev/bomly-sdk/model"
)

// applyIngestedAssertions carries a source document's own claims onto the
// node, so a conversion keeps what the document said (issue #396).
//
// Only coordinates, scope, copyright and licenses used to survive this hop,
// so `bomly scan --sbom --format spdx` silently returned a document asserting
// far less than its input. These are the fields ADR-0037 typed for exactly
// that reason.
//
// Every value clears its own gate here. An ingested document is untrusted
// input that Bomly re-emits under its own name: a supplier name carrying
// control characters would corrupt SPDX's line-oriented form, a reference
// locator can be a local path or carry credentials, and #391 leaked
// credentials twice through URL positions its author had not considered. The
// gates are the SDK's, so ingest cannot hold a value to a weaker standard
// than export does.
//
// What is deliberately not set here is Source. It feeds
// RegistryMatchEligible, and an ingested component must stay eligible for
// enrichment so `bomly scan --sbom --enrich` keeps working.
func applyIngestedAssertions(pkg *model.DependencyNode, component Component) {
	if pkg == nil {
		return
	}
	if component.Supplier != nil {
		if contact, ok := component.Supplier.Normalized(); ok {
			pkg.Supplier = &contact
		}
	}
	if component.Originator != nil {
		if contact, ok := component.Originator.Normalized(); ok {
			pkg.Originator = &contact
		}
	}
	pkg.Description = model.NormalizeDescription(component.Description)
	pkg.Homepage = model.NormalizeHomepage(component.Homepage)
	pkg.ExternalReferences = model.MergeExternalReferences(nil, component.ExternalReferences)
	pkg.Digests = ingestedDigests(component.Digests)
	pkg.CPEs = ingestedCPEs(component.CPEs)
}

// ingestedDigests admits the checksums a document stated, each through the
// digest gate.
//
// A digest names an algorithm from a vocabulary both formats keep extending,
// and a value whose shape that algorithm fixes; a document may state neither
// correctly. Digest.Normalized is the gate, so the algorithm set stays the
// SDK's -- a length check written here would go stale in the direction of
// silently dropping a real hash, which is precisely how a transcribed digest
// table lost CycloneDX's Streebog entries once already.
func ingestedDigests(digests []Digest) []model.Digest {
	if len(digests) == 0 {
		return nil
	}
	admitted := make([]model.Digest, 0, len(digests))
	seen := make(map[model.Digest]struct{}, len(digests))
	for _, digest := range digests {
		normalized, ok := model.Digest{
			Algorithm: model.DigestAlgorithm(digest.Algorithm),
			Value:     digest.Value,
		}.Normalized()
		if !ok {
			continue
		}
		if _, duplicate := seen[normalized]; duplicate {
			continue
		}
		seen[normalized] = struct{}{}
		admitted = append(admitted, normalized)
	}
	if len(admitted) == 0 {
		return nil
	}
	return admitted
}

// ingestedCPEs admits the CPEs a document stated, dropping any that is not a
// well-formed binding. A malformed identifier published back out would be a
// claim about a platform no source made, and a CPE decides which advisories
// match -- a wrong one is a wrong vulnerability answer.
//
// The grammar is the SDK's. It is reachable only through the external-
// reference gate, so each value is offered as a reference under both CPE
// reference types and admitted if either accepts it: 2.2 and 2.3 are
// genuinely different bindings, and a value is whichever one it parses as.
// Writing the grammar here instead is the mistake #396 records being
// retrofitted once already -- the hand-rolled CPE validator its fuzz target
// immediately broke.
func ingestedCPEs(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	cpeTypes := []string{spdxcommon.TypeSecurityCPE23Type, spdxcommon.TypeSecurityCPE22Type}
	admitted := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		for _, cpeType := range cpeTypes {
			reference, ok := model.ExternalReference{
				Category: model.ExternalReferenceCategorySecurity,
				Type:     cpeType,
				Locator:  value,
			}.Normalized()
			if !ok {
				continue
			}
			if _, duplicate := seen[reference.Locator]; duplicate {
				break
			}
			seen[reference.Locator] = struct{}{}
			admitted = append(admitted, reference.Locator)
			break
		}
	}
	if len(admitted) == 0 {
		return nil
	}
	return admitted
}

// componentIdentityHint describes a component in an error, preferring the
// package URL it stated because that is the field an author has to correct.
func componentIdentityHint(component Component) string {
	if purl := strings.TrimSpace(component.PURL); purl != "" {
		return "purl " + purl
	}
	name := strings.TrimSpace(component.Name)
	if name == "" {
		return "unnamed component"
	}
	if version := strings.TrimSpace(component.Version); version != "" {
		return "name " + name + "@" + version
	}
	return "name " + name
}

// ToGraph converts a neutral SBOM document back into a dependency graph.
func ToGraph(doc *Document) (*model.Graph, error) {
	depsGraph, _, err := toGraph(doc)
	return depsGraph, err
}

// ToGraphEntry converts a document into one manifest-scoped graph entry:
// the graph ToGraph builds, the document's own assertions, and -- carried in
// Packages, where consolidation folds them into the registry -- what the
// document asserted about its packages that a graph node cannot hold: the
// advisories it listed for a component, with their VEX analysis, and a
// component's end-of-life record. Before this, both were read from the
// document and dropped at this hop, so a document that said a package was
// vulnerable, or not affected, produced a graph that said neither.
//
// Only components that carried one or the other get a package; the rest are
// what the graph already says. Two components that mint one identity fold
// into one package under the registry's merge classes. The slice is ordered
// by package URL.
func ToGraphEntry(doc *Document, manifest model.ManifestMetadata) (model.GraphEntry, error) {
	depsGraph, idMap, err := toGraph(doc)
	if err != nil {
		return model.GraphEntry{}, err
	}
	entry := model.GraphEntry{Graph: depsGraph, Manifest: manifest, Document: DocumentAssertionsFor(doc)}
	byPURL := make(map[string]*model.Package)
	for _, component := range doc.Components {
		if len(component.Vulnerabilities) == 0 && component.EOL == nil {
			continue
		}
		nodeID, ok := idMap[component.ID]
		if !ok {
			continue
		}
		node, ok := depsGraph.DependencyNode(nodeID)
		if !ok {
			continue
		}
		pkg := model.PackageFromDependencyNode(node)
		pkg.Vulnerabilities = packageVulnerabilities(component.Vulnerabilities)
		pkg.EOL = packageEOL(component.EOL)
		if existing, dup := byPURL[pkg.PURL]; dup {
			existing.MergeFrom(pkg)
			continue
		}
		byPURL[pkg.PURL] = pkg
	}
	if len(byPURL) > 0 {
		entry.Packages = make([]*model.Package, 0, len(byPURL))
		for _, pkg := range byPURL {
			entry.Packages = append(entry.Packages, pkg)
		}
		sort.Slice(entry.Packages, func(i, j int) bool { return entry.Packages[i].PURL < entry.Packages[j].PURL })
	}
	return entry, nil
}

// packageVulnerabilities is the ingest-side inverse of
// vulnerabilitiesFromPackage: what a document's advisory record maps onto the
// registry's OSV-aligned shape. The recommendation is not carried -- the
// exporter derives it from the fixed versions -- and the severity band,
// first rating, CWEs, advisory URLs, description, fixed versions and
// analysis are.
func packageVulnerabilities(vulns []Vulnerability) []model.Vulnerability {
	out := make([]model.Vulnerability, 0, len(vulns))
	for _, v := range vulns {
		if strings.TrimSpace(v.ID) == "" {
			continue
		}
		vuln := model.Vulnerability{
			ID:             v.ID,
			Source:         v.Source,
			ParsedSeverity: model.ParseSeverityLevel(v.Severity),
			Details:        v.Description,
			FixedVersions:  append([]string(nil), v.FixedVersions...),
			Analysis:       v.Analysis.Clone(),
		}
		if v.Score != nil || v.Vector != "" {
			score := model.CVSSScore{Vector: v.Vector, Version: model.SeverityType(cvssVersionForMethod(v.Method)), Source: v.Source}
			if v.Score != nil {
				score.Score = *v.Score
			}
			vuln.CVSS = []model.CVSSScore{score}
		}
		for _, cwe := range v.CWEs {
			if cwe > 0 {
				vuln.CWEs = append(vuln.CWEs, model.CWE{ID: fmt.Sprintf("CWE-%d", cwe)})
			}
		}
		for _, url := range v.Advisories {
			if url = strings.TrimSpace(url); url != "" {
				vuln.References = append(vuln.References, model.Reference{URL: url, Type: model.ReferenceTypeAdvisory})
			}
		}
		out = append(out, vuln)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// cvssVersionForMethod is the inverse of cvssMethodForVersion: the CVSS
// version a CycloneDX scoring method names, or "" for a method that is not
// a CVSS version.
func cvssVersionForMethod(method string) string {
	switch strings.TrimSpace(method) {
	case "CVSSv2":
		return "2.0"
	case "CVSSv3":
		return "3.0"
	case "CVSSv31":
		return "3.1"
	case "CVSSv4":
		return "4.0"
	default:
		return ""
	}
}

// packageEOL projects a document's end-of-life record onto the registry's.
// Source is left empty: it names the matcher that asserted the record, and
// a document is not one.
func packageEOL(eol *EOL) *model.PackageEOL {
	if eol == nil {
		return nil
	}
	return &model.PackageEOL{EOL: eol.EOL, EOLDate: eol.EOLDate, Cycle: eol.Cycle, LatestVersion: eol.LatestVersion}
}

// toGraph builds the graph and returns the mapping from each component's
// document ID to the node identity its coordinates minted, which is what
// ToGraphEntry needs to attach package facts to the right node.
func toGraph(doc *Document) (*model.Graph, map[string]string, error) {
	if doc == nil {
		return nil, nil, ErrNilDocument
	}

	depsGraph := model.New()
	idMap := make(map[string]string, len(doc.Components))
	skipped := make(map[string]struct{})
	for _, component := range doc.Components {
		if isDocumentRootPseudoPackage(component, doc.isDescribed(component.ID)) {
			skipped[component.ID] = struct{}{}
			continue
		}
		ecosystem := ComponentEcosystem(component)
		packageManager := model.PackageManagerUnknown
		if manager, err := model.ParsePackageManager(component.PackageManager); err == nil {
			packageManager = manager
		}
		if packageManager == model.PackageManagerUnknown {
			packageManager = packageManagerForPURL(component.PURL, string(ecosystem), component.PackageManager)
		}
		// Identity is minted by the constructor (ADR-0041): a node's ID is
		// its canonical package URL, so the ingested component ID is not
		// carried in.
		pkg, err := model.NewDependencyNode(model.Coordinates{
			Name:           component.Name,
			Version:        component.Version,
			Org:            ingestedCoordinateOrg(component),
			Ecosystem:      ecosystem,
			PackageManager: packageManager,
			Type:           model.ParsePackageType(component.Type),
			PURL:           strings.TrimSpace(component.PURL),
		})
		if err != nil {
			// Loudly, not silently. This used to `continue`, which dropped
			// the component and every relationship naming it -- so an SBOM
			// carrying one malformed package URL produced a smaller graph,
			// and a scan of it reported clean while a genuinely vulnerable
			// dependency was simply absent from the answer. Under-reporting
			// a vulnerability is the worst way for a security tool to fail,
			// and it is exactly what a corrupt document should not be able
			// to buy.
			//
			// Refusing the document is the same rule ADR-0041 applies at the
			// plugin wire: an identity that cannot mint a well-formed package
			// URL is an error, with no lenient path and no pkg:generic
			// coercion. The message names the component so the author can
			// find it, since the fix is in their document rather than here.
			return nil, nil, fmt.Errorf("sbom component %q (%s): %w", component.ID, componentIdentityHint(component), err)
		}
		pkg.Scopes = append([]model.Scope(nil), component.Scopes...)
		// Through the gate, not copied: the field crosses the same trust
		// boundary every other ingested assertion does.
		pkg.SourceScope = model.NormalizeSourceScope(component.SourceScope)
		pkg.Copyright = model.NormalizeCopyright(component.Copyright)
		applyIngestedAssertions(pkg, component)
		// The document's own component ID does not survive: the node answers
		// to the identity its coordinates mint, and idMap below is what
		// re-points the document's relationships onto it.
		packageID := pkg.NodeID()
		model.SetDetectionLicenses(pkg, graphLicenses(component.Licenses))

		// Through the SDK's fold, not a lookup followed by an insert. Two
		// components can mint one canonical package URL -- the same package
		// listed twice, or listed once per manifest -- and skipping the second
		// discarded everything it asserted: its supplier, its references, its
		// digests. InsertNode applies the declared merge classes instead,
		// scalars filling gaps and sets unioning (ADR-0041).
		if _, err := depsGraph.InsertNode(pkg); err != nil {
			return nil, nil, fmt.Errorf("add package %q: %w", component.ID, err)
		}
		idMap[component.ID] = packageID
	}

	for _, dependency := range doc.Dependencies {
		if _, ok := skipped[dependency.Ref]; ok {
			continue
		}
		fromID, ok := idMap[dependency.Ref]
		if !ok {
			// Dependency entries may reference the synthesized document root
			// (present only in CycloneDX metadata.component) or otherwise
			// dangling refs; neither has a graph node to anchor an edge.
			continue
		}
		for _, child := range dependency.DependsOn {
			if _, ok := skipped[child]; ok {
				continue
			}
			toID, ok := idMap[child]
			if !ok {
				continue
			}
			if fromID == toID {
				continue
			}
			if err := depsGraph.AddEdge(fromID, toID); err != nil {
				return nil, nil, fmt.Errorf("add dependency %q -> %q: %w", fromID, toID, err)
			}
		}
	}

	return depsGraph, idMap, nil
}

// isDocumentRootPseudoPackage reports whether a component stands for the
// scanned tree rather than for a package, so the graph steps through it and
// its children become roots.
//
// Bomly's synthesized project root is one, by its identifier; it carries a
// pkg:generic PURL but is still a stand-in. Another producer's is the subject
// its document names -- CycloneDX metadata.component, an SPDX DESCRIBES
// target -- with neither a package URL nor a version: syft's scanned
// directory (a file), trivy's "." (an application). Nothing identifies such a
// subject as a package, so there is nothing to match, audit, or report it as.
//
// The rule is keyed on the subject, not on the type. It used to drop every
// versionless, PURL-less component typed "file", and FILE is a valid SPDX
// package purpose, so a real file package in the inventory vanished from the
// graph along with its relationships.
func isDocumentRootPseudoPackage(component Component, described bool) bool {
	if IsProjectRootComponent(component) {
		return true
	}
	return described && strings.TrimSpace(component.PURL) == "" && strings.TrimSpace(component.Version) == ""
}

// ingestedCoordinateOrg returns the namespace to carry on an ingested
// package's coordinates.
//
// SBOM producers split a namespaced package two ways. Bomly writes the whole
// ecosystem-native name ("@scope/pkg", "github.com/google/uuid") and repeats
// the namespace in `group`; most others write a bare name plus the namespace
// in `group`. Coordinates joins Org with Name to rebuild the display name, so
// which split arrived decides whether Org may be set at all: setting it on an
// already-qualified name yields "@scope/@scope/pkg", and leaving it unset on a
// bare name loses the namespace entirely.
//
// The name itself is never rewritten. Detectors and export both treat it as
// the ecosystem-native identity, so this only fills in the namespace when the
// name does not already carry it.
func ingestedCoordinateOrg(component Component) string {
	namespace := strings.TrimSpace(component.Org)
	if purl := parsePURL(component.PURL); purl != nil {
		if fromPURL := strings.TrimSpace(purl.Namespace); fromPURL != "" {
			// The PURL is the stronger claim: it is structured, and export
			// derives `group` from it in the first place.
			namespace = fromPURL
		}
	}
	if namespace == "" {
		return ""
	}

	// Compared case-insensitively: PURL normalization lowercases the namespace
	// for some types, so a Go module's namespace arrives as
	// "github.com/burntsushi" while its name keeps "github.com/BurntSushi/toml".
	// A case-sensitive test would miss that and double the namespace.
	name := strings.TrimSpace(component.Name)
	lowerName := strings.ToLower(name)
	lowerNamespace := strings.ToLower(namespace)
	if lowerName == lowerNamespace {
		return ""
	}
	// "/" separates npm scopes and Go module paths; ":" separates Maven
	// coordinates. A name already starting with the namespace and a separator
	// carries it, so Org must stay empty to avoid doubling it.
	for _, separator := range []string{"/", ":"} {
		if strings.HasPrefix(lowerName, lowerNamespace+separator) {
			return ""
		}
	}
	return namespace
}

func graphLicenses(licenses []License) []model.PackageLicense {
	if len(licenses) == 0 {
		return nil
	}
	out := make([]model.PackageLicense, 0, len(licenses))
	for _, license := range licenses {
		out = append(out, model.PackageLicense{
			Value:          license.Value,
			SPDXExpression: license.SPDXExpression,
			Type:           model.LicenseType(license.Type),
		})
	}
	return out
}
