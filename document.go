package sdk

import (
	"sort"
	"strings"
)

// Both formats carry claims about the document itself, distinct from claims
// about any component in it: who produced it, when, under what data license,
// and which document it is. SPDX puts them in CreationInfo and the document
// header; CycloneDX puts them in metadata.
//
// They belong on GraphEntry rather than on the scan, because an entry is what
// a document maps to. A scan that read three SBOMs read three sets of these,
// and collapsing them loses the ability to say which claim came from where --
// which is exactly what a merged export needs in order to link back to its
// sources.

// maxDocumentFieldLength bounds a free-text document field. These arrive from
// an untrusted SBOM and are written back into a document.
const maxDocumentFieldLength = 4096

// DocumentTool is one tool that produced a document.
//
// Both formats record this, and neither models it the same way -- SPDX writes
// a creator string, CycloneDX a structured tool entry -- so the structured
// form is kept and the flat one rendered from it, never the reverse.
type DocumentTool struct {
	// Vendor is the organization that publishes the tool. Optional.
	Vendor string `json:"vendor,omitempty"`
	// Name is the tool's name. A tool without one is not a tool.
	Name string `json:"name,omitempty"`
	// Version is the tool's version, when the document stated it.
	Version string `json:"version,omitempty"`
}

// Normalized returns the tool with its fields bounded and trimmed, and reports
// whether anything publishable remains. A tool with no name is dropped: a
// version with nothing to attach it to says nothing.
func (t DocumentTool) Normalized() (DocumentTool, bool) {
	normalized := DocumentTool{
		Vendor:  strings.TrimSpace(t.Vendor),
		Name:    strings.TrimSpace(t.Name),
		Version: strings.TrimSpace(t.Version),
	}
	for _, field := range []string{normalized.Vendor, normalized.Name, normalized.Version} {
		if len(field) > maxDocumentFieldLength || containsControlChar(field) {
			return DocumentTool{}, false
		}
	}
	if normalized.Name == "" {
		return DocumentTool{}, false
	}
	return normalized, true
}

// DocumentAssertions are the claims a source document makes about itself,
// carried per GraphEntry so a merged export can say which claim came from
// which document.
type DocumentAssertions struct {
	// Identity is the document's own identifier: SPDX's documentNamespace, or
	// a CycloneDX BOM-Link ("urn:cdx:<serial>/<version>"). It is held to the
	// IRI rule rather than the web-URL rule, because a BOM-Link is a URN and
	// the web gate would reject the identifier a merged export links back to.
	Identity string `json:"identity,omitempty"`
	// Name is the document's stated name.
	Name string `json:"name,omitempty"`
	// DataLicense is the license of the document's own data, which SPDX
	// requires and CycloneDX does not model. Held to the same expression rule
	// as a package license, so an unparseable value is dropped rather than
	// written into a field consumers read as an SPDX expression.
	DataLicense string `json:"data_license,omitempty"`
	// Created is the document's timestamp, as the source stated it. Kept
	// verbatim: re-rendering a timestamp is a change to a claim, and the two
	// formats agree on RFC 3339 anyway.
	Created string `json:"created,omitempty"`
	// Creators are the parties credited with producing the document. Contact
	// carries no email, per ADR-0037's deferred privacy review.
	Creators []Contact `json:"creators,omitempty"`
	// Tools are the tools credited with producing the document.
	Tools []DocumentTool `json:"tools,omitempty"`
	// Comment is the document-level comment.
	Comment string `json:"comment,omitempty"`
}

// Normalized returns the assertions with every field held to its gate, and
// reports whether anything publishable remains.
//
// Each field is gated independently: a document with an unusable data license
// and a good identity keeps the identity. Dropping the whole record because
// one field failed would lose the link a merged export needs.
func (d DocumentAssertions) Normalized() (DocumentAssertions, bool) {
	var normalized DocumentAssertions

	// Through the same locator rule an external reference uses, not one of
	// its branches. A document identity is an SPDX namespace (a web URL), a
	// CycloneDX BOM-Link (whose grammar cyclonedx-go owns), or another IRI --
	// which is exactly the IRI dispatch. Calling the generic IRI fallback
	// directly skipped both of the first two, so it rejected the BOM-Link
	// this field exists to carry.
	if identity, ok := normalizeLocator(strings.TrimSpace(d.Identity), LocatorKindIRI); ok {
		normalized.Identity = identity
	}
	normalized.Name = NormalizeDescription(d.Name)
	if len(normalized.Name) > maxDocumentFieldLength {
		normalized.Name = ""
	}
	// No extracted text: a document's data license is a spec-listed
	// identifier ("CC0-1.0"), never a minted LicenseRef whose text lives
	// elsewhere, and passing "" is what makes the shared rule refuse one.
	normalized.DataLicense = normalizedSPDXExpression(d.DataLicense, "")
	if created := strings.TrimSpace(d.Created); created != "" &&
		len(created) <= maxDocumentFieldLength && !containsControlChar(created) {
		normalized.Created = created
	}
	normalized.Comment = NormalizeDescription(d.Comment)
	if len(normalized.Comment) > maxDocumentFieldLength {
		normalized.Comment = ""
	}

	for _, creator := range d.Creators {
		if contact, ok := creator.Normalized(); ok {
			normalized.Creators = append(normalized.Creators, contact)
		}
	}
	for _, tool := range d.Tools {
		if cleaned, ok := tool.Normalized(); ok {
			normalized.Tools = append(normalized.Tools, cleaned)
		}
	}
	// Sorted, because a document is built from these and two runs that read
	// the same creators in a different order must produce the same bytes.
	sort.SliceStable(normalized.Creators, func(i, j int) bool {
		return creatorKey(normalized.Creators[i]) < creatorKey(normalized.Creators[j])
	})
	sort.SliceStable(normalized.Tools, func(i, j int) bool {
		return toolKey(normalized.Tools[i]) < toolKey(normalized.Tools[j])
	})

	return normalized, !normalized.IsEmpty()
}

// IsEmpty reports whether the assertions carry nothing.
func (d DocumentAssertions) IsEmpty() bool {
	return d.Identity == "" && d.Name == "" && d.DataLicense == "" &&
		d.Created == "" && d.Comment == "" && len(d.Creators) == 0 && len(d.Tools) == 0
}

// Clone returns a deep copy.
func (d DocumentAssertions) Clone() DocumentAssertions {
	clone := d
	if len(d.Creators) > 0 {
		clone.Creators = append([]Contact(nil), d.Creators...)
	}
	if len(d.Tools) > 0 {
		clone.Tools = append([]DocumentTool(nil), d.Tools...)
	}
	return clone
}

// MergeDocumentAssertions combines two sets of document claims.
//
// Scalars fill gaps only: two documents disagreeing about their own name is
// not something to resolve by picking one, so the first stated value stands
// and the second is dropped rather than overwriting it. Creators and tools
// union, because two documents having produced a merged one is the normal
// case and both deserve credit.
//
// Both sides are gated on the way in. An unpublishable value must not become
// visible in-process just because it arrived through a merge rather than
// through a constructor.
func MergeDocumentAssertions(dst, src DocumentAssertions) DocumentAssertions {
	left, _ := dst.Normalized()
	right, _ := src.Normalized()

	merged := left
	if merged.Identity == "" {
		merged.Identity = right.Identity
	}
	if merged.Name == "" {
		merged.Name = right.Name
	}
	if merged.DataLicense == "" {
		merged.DataLicense = right.DataLicense
	}
	if merged.Created == "" {
		merged.Created = right.Created
	}
	if merged.Comment == "" {
		merged.Comment = right.Comment
	}
	for _, creator := range right.Creators {
		if !containsCreator(merged.Creators, creator) {
			merged.Creators = append(merged.Creators, creator)
		}
	}
	for _, tool := range right.Tools {
		if !containsTool(merged.Tools, tool) {
			merged.Tools = append(merged.Tools, tool)
		}
	}
	sort.SliceStable(merged.Creators, func(i, j int) bool {
		return creatorKey(merged.Creators[i]) < creatorKey(merged.Creators[j])
	})
	sort.SliceStable(merged.Tools, func(i, j int) bool {
		return toolKey(merged.Tools[i]) < toolKey(merged.Tools[j])
	})
	return merged
}

func creatorKey(c Contact) string { return string(c.Kind) + "\x00" + c.Name + "\x00" + c.URL }

func toolKey(t DocumentTool) string { return t.Vendor + "\x00" + t.Name + "\x00" + t.Version }

func containsCreator(list []Contact, want Contact) bool {
	key := creatorKey(want)
	for _, item := range list {
		if creatorKey(item) == key {
			return true
		}
	}
	return false
}

func containsTool(list []DocumentTool, want DocumentTool) bool {
	key := toolKey(want)
	for _, item := range list {
		if toolKey(item) == key {
			return true
		}
	}
	return false
}

// PackageNodeIndex maps a package reference to the dependency nodes that
// resolved to it.
//
// It is derived, never stored. The stored truth stays DependencyNode's
// PackageRef -- one pointer per node to the package it matched -- and the
// registry stays position-free, holding packages keyed by PURL and nothing
// about where they were found. Storing the reverse direction as well would
// give the same fact two homes that can disagree, and the one that goes stale
// is always the derived-looking one.
//
// Build it when a question needs it and discard it: it is a view over a graph
// that is being mutated, not a record.
type PackageNodeIndex map[string][]*DependencyNode

// IndexNodesByPackage builds the reverse index for a graph. Nodes with no
// package reference are omitted, and each entry is ordered by node ID so a
// caller iterating it gets a stable answer.
func IndexNodesByPackage(g *Graph) PackageNodeIndex {
	index := PackageNodeIndex{}
	if g == nil {
		return index
	}
	for _, node := range g.DependencyNodes() {
		if node == nil || node.PackageRef == "" {
			continue
		}
		index[node.PackageRef] = append(index[node.PackageRef], node)
	}
	for ref := range index {
		nodes := index[ref]
		sort.SliceStable(nodes, func(i, j int) bool { return nodes[i].NodeID() < nodes[j].NodeID() })
	}
	return index
}

// Nodes returns the dependency nodes that resolved to a package reference, or
// nil when none did.
func (i PackageNodeIndex) Nodes(packageRef string) []*DependencyNode {
	if i == nil {
		return nil
	}
	return i[packageRef]
}

// Usages returns every usage of a package across the graph the index was built
// from, joined to reachability evidence and filtered.
//
// This is the reverse index earning its place: a vulnerability names a
// package, and the question "is it reachable at runtime anywhere" is about the
// nodes that package resolved to. Without the index a caller walks the whole
// graph per vulnerability.
func (i PackageNodeIndex) Usages(packageRef string, evidence []ReachabilityEvidence, filter UsageFilter) []Usage {
	var usages []Usage
	for _, node := range i.Nodes(packageRef) {
		usages = append(usages, SelectUsages(node, evidence, filter)...)
	}
	return usages
}
