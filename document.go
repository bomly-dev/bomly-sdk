package sdk

import (
	"encoding/json"
	"sort"
	"strings"
	"unicode/utf8"

	cdx "github.com/CycloneDX/cyclonedx-go"
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

// maxDocumentSources bounds the documents one document may claim to be built
// from. A merged export names a handful; the allowance leaves room for a deep
// merge history without letting an ingested document mint thousands of
// external references on the next export. A count, kept dumb.
const maxDocumentSources = 256

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
		if !documentFieldPublishable(field) {
			return DocumentTool{}, false
		}
	}
	if normalized.Name == "" {
		return DocumentTool{}, false
	}
	return normalized, true
}

// DocumentSource names one document another document was built from: the
// link tuple a merged export needs to reference it. It is the same tuple
// DocumentAssertions carries for the document itself -- identity, version,
// checksum -- because a reference is written from exactly those. An SPDX
// externalDocumentRef requires the checksum on every entry, so a list of bare
// identities could not be re-exported as valid SPDX references at all; and the
// wire is frozen once shipped, so the record has to carry it from the start.
//
// Gates: Identity is required and held to the IRI rule Identity is held to;
// Version is a positive integer that agrees with a BOM-Link identity's tail;
// Checksum passes the digest gate with the artifact subject. Each is the rule
// the document's own field follows, stated once in the shared helpers.
type DocumentSource struct {
	// Identity is the source document's own identifier.
	Identity string `json:"identity,omitempty"`
	// Version is the source document's version, when the reference stated it.
	Version int `json:"version,omitempty"`
	// Checksum is a digest over the source document's original bytes, when
	// the reference carried one -- SPDX always does.
	Checksum *Digest `json:"checksum,omitempty"`
}

// Normalized returns the source with each field held to its gate, and reports
// whether it still names a document. A source with no publishable identity
// names nothing and is dropped whole; the other two fields drop individually.
func (s DocumentSource) Normalized() (DocumentSource, bool) {
	identity, ok := normalizeLocator(strings.TrimSpace(s.Identity), LocatorKindIRI)
	if !ok {
		return DocumentSource{}, false
	}
	normalized := DocumentSource{Identity: identity}
	normalized.Version = documentVersionFor(identity, s.Version)
	normalized.Checksum = documentChecksumFor(s.Checksum)
	return normalized, true
}

// Clone returns a deep copy.
func (s DocumentSource) Clone() DocumentSource {
	clone := s
	if s.Checksum != nil {
		checksum := *s.Checksum
		clone.Checksum = &checksum
	}
	return clone
}

// documentSourceWire carries DocumentSource's fields without its methods, so
// the codec hooks can encode and decode without recursing.
type documentSourceWire DocumentSource

// MarshalJSON applies the gates on the way out, so a hand-built source is held
// to them at the wire like every other untrusted-input field.
func (s DocumentSource) MarshalJSON() ([]byte, error) {
	normalized, _ := s.Normalized()
	return json.Marshal(documentSourceWire(normalized))
}

// UnmarshalJSON applies the gates on the way in. A source that names nothing
// decodes to the zero value, which the parent's gate then drops.
func (s *DocumentSource) UnmarshalJSON(data []byte) error {
	var wire documentSourceWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	normalized, _ := DocumentSource(wire).Normalized()
	*s = normalized
	return nil
}

// documentVersionFor is the version gate shared by a document and its
// sources: a positive integer, and one that agrees with the version a
// BOM-Link identity names in its tail. A payload stating urn:cdx:<serial>/1
// beside Version 2 is contradicting itself, and carrying both would let an
// export identify version 1 while asserting version 2. The stated version is
// the one dropped: the identity is the link a merged export needs, and it
// still says which version it names. The grammar is cyclonedx-go's --
// ParseBOMLink reads the tail; nothing is parsed here. An SPDX namespace
// carries no version, so any stated one stands there. A missing version is
// not filled from the link: that would write a version onto every existing
// BOM-Link payload that never stated one.
func documentVersionFor(identity string, version int) int {
	if version <= 0 {
		return 0
	}
	if cdx.IsBOMLink(identity) {
		if link, err := cdx.ParseBOMLink(identity); err == nil && link.Version() != version {
			return 0
		}
	}
	return version
}

// documentChecksumFor is the checksum gate shared by a document and its
// sources: the digest gate as a whole, so an unpublishable digest is dropped
// rather than carried as a zero record, plus the artifact subject. The digest
// vocabulary lets a package record say its hash covers a source tree or a
// metadata record instead; a document checksum promises the original bytes,
// and the SPDX external-document checksum has no subject slot to carry the
// distinction, so a digest of anything else would be published as a checksum
// for the wrong object.
func documentChecksumFor(checksum *Digest) *Digest {
	if checksum == nil {
		return nil
	}
	normalized, ok := checksum.Normalized()
	if !ok || normalized.Subject != DigestSubjectArtifact {
		return nil
	}
	return &normalized
}

// sameDocumentLink reports whether two link tuples name the same document:
// the same identity at a compatible version. Two stated versions that differ
// are two documents sharing a namespace, and filling across them would pair
// version 1 with version 2's hash.
func sameDocumentLink(identity string, version int, otherIdentity string, otherVersion int) bool {
	return identity != "" && identity == otherIdentity &&
		(version == 0 || otherVersion == 0 || version == otherVersion)
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
	// Version is the document's own version number: CycloneDX's top-level
	// version, which a BOM-Link's "/<n>" tail repeats, and which SPDX 2.x
	// leaves implicit at 1. Zero means the source stated none; the default is
	// the exporting format's to apply, not this carrier's, so an entry that
	// never stated a version keeps writing the bytes it wrote before the
	// field existed.
	//
	// Gate: a positive integer, else absent. Merge class: fill-gaps, as one
	// provenance tuple with Identity and Checksum -- see
	// MergeDocumentAssertions.
	Version int `json:"version,omitempty"`
	// Checksum is a digest over the source document's original bytes,
	// computed at ingest while those bytes are in hand: it cannot be
	// recovered from the parsed model later, and an SPDX externalDocumentRef
	// is invalid without one, so a merged export that lacks it cannot name
	// its sources at all.
	//
	// Gate: Digest.Normalized, the same one a package digest passes, plus
	// the artifact subject: a digest over a source tree or a metadata record
	// is not a hash of the document's bytes, and the SPDX reference has no
	// slot to say so. Merge class: fill-gaps, as one provenance tuple with
	// Identity and Version --
	// a checksum is a claim about one document's bytes and never attaches
	// to another document's identity. See MergeDocumentAssertions.
	Checksum *Digest `json:"checksum,omitempty"`
	// Sources are the documents this one was built from, when it said so:
	// SPDX externalDocumentRefs, or CycloneDX external references of type
	// "bom". A merged export writes one link per source (ADR-0037); without
	// somewhere to read them back into, a single ingest of that export lost
	// every trace of its inputs.
	//
	// Gate: each entry passes DocumentSource.Normalized; entries naming the
	// same document fold, with version and checksum filling gaps; the list
	// is sorted for byte-stable output and bounded by maxDocumentSources,
	// applied to the input before any work is done on it. An entry naming
	// the document's own Identity is dropped: a document is not built from
	// itself, and recording it would write a cycle. Merge class: set, unioned
	// by document -- a document built from a merged document inherits that
	// document's sources beside its own identity, so provenance survives
	// more than one hop.
	Sources []DocumentSource `json:"sources,omitempty"`
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
	// A name is a single-line field: SPDX writes it as "DocumentName: <v>",
	// so a line break in it corrupts the tag form outright. That rules out
	// NormalizeDescription, which deliberately keeps line breaks because a
	// description is genuinely multi-line -- the fuzzer caught the reuse.
	if name := strings.TrimSpace(d.Name); name != "" && documentFieldPublishable(name) {
		normalized.Name = name
	}
	// No extracted text: a document's data license is a spec-listed
	// identifier ("CC0-1.0"), never a minted LicenseRef whose text lives
	// elsewhere, and passing "" is what makes the shared rule refuse one.
	normalized.DataLicense = normalizedSPDXExpression(d.DataLicense, "")
	if created := strings.TrimSpace(d.Created); created != "" && documentFieldPublishable(created) {
		normalized.Created = created
	}
	// A comment is multi-line in both formats -- SPDX wraps it in <text> --
	// so the description gate is the right one here, line breaks and all.
	normalized.Comment = NormalizeDescription(d.Comment)
	if len(normalized.Comment) > maxDocumentFieldLength {
		normalized.Comment = ""
	}
	// The document's own link tuple takes the gates its sources take: the
	// rules are the same because a reference is written from the same three
	// fields, and stating them once keeps the two from drifting.
	normalized.Version = documentVersionFor(normalized.Identity, d.Version)
	normalized.Checksum = documentChecksumFor(d.Checksum)

	// Sources take their gate one by one: a link a merged export cannot
	// write is not worth carrying, and one entry failing must not lose the
	// others. Entries naming the same document fold, sorted so two runs that
	// read the same references in a different order produce the same bytes.
	//
	// The bound is applied to the input, before any of that work: an
	// ingested document controls how many entries it claims, and bounding
	// only the published list would let a list of ten thousand -- even one
	// of duplicates or junk -- cost ten thousand gate passes and a map that
	// size. Entries past the bound are not read at all.
	sources := d.Sources
	if len(sources) > maxDocumentSources {
		sources = sources[:maxDocumentSources]
	}
	for _, source := range sources {
		cleaned, ok := source.Normalized()
		if !ok || cleaned.Identity == normalized.Identity {
			continue
		}
		folded := false
		for i := range normalized.Sources {
			existing := &normalized.Sources[i]
			if sameDocumentLink(existing.Identity, existing.Version, cleaned.Identity, cleaned.Version) {
				existing.Version = MergeFillGap(existing.Version, cleaned.Version, nil)
				existing.Checksum = MergeFillGap(existing.Checksum, cleaned.Checksum, nil)
				folded = true
				break
			}
		}
		if !folded {
			normalized.Sources = append(normalized.Sources, cleaned)
		}
	}
	sort.SliceStable(normalized.Sources, func(i, j int) bool {
		if normalized.Sources[i].Identity != normalized.Sources[j].Identity {
			return normalized.Sources[i].Identity < normalized.Sources[j].Identity
		}
		return normalized.Sources[i].Version < normalized.Sources[j].Version
	})

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

// documentFieldPublishable is the gate a single-line document field passes:
// bounded, valid UTF-8, no control characters. Invalid UTF-8 is refused rather
// than carried for the reason Digest.Validate gives: encoding/json rewrites
// such bytes to U+FFFD, so a value that passed the gate would serialize as a
// different value than the one checked -- and the codec round trip the fuzz
// target asserts would not be a fixed point. The fuzzer found exactly that on
// the document name once the codec hooks made the round trip observable.
func documentFieldPublishable(field string) bool {
	return len(field) <= maxDocumentFieldLength && utf8.ValidString(field) && !containsControlChar(field)
}

// documentAssertionsWire carries DocumentAssertions' fields without its
// methods, so the codec hooks below can encode and decode without recursing.
type documentAssertionsWire DocumentAssertions

// MarshalJSON applies every field's gate on the way out, so a hand-built
// value that bypassed Normalized is still held to it at the wire. Without
// this a negative version reached a reader unchanged, and a checksum the
// digest codec had zeroed still encoded as "checksum":{} -- a non-nil record
// an exporter would read as a checksum being present.
func (d DocumentAssertions) MarshalJSON() ([]byte, error) {
	normalized, _ := d.Normalized()
	return json.Marshal(documentAssertionsWire(normalized))
}

// UnmarshalJSON applies the same gates on the way in, so a payload from a
// plugin or an older producer is held to them whether or not the caller
// remembers to call Normalized. A record that gates to nothing decodes to
// the zero value rather than failing the payload: the entry it belongs to is
// still a graph, and a document with no publishable claims is merely absent.
func (d *DocumentAssertions) UnmarshalJSON(data []byte) error {
	var wire documentAssertionsWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	normalized, _ := DocumentAssertions(wire).Normalized()
	*d = normalized
	return nil
}

// IsEmpty reports whether the assertions carry nothing.
func (d DocumentAssertions) IsEmpty() bool {
	return d.Identity == "" && d.Name == "" && d.DataLicense == "" &&
		d.Created == "" && d.Comment == "" && len(d.Creators) == 0 && len(d.Tools) == 0 &&
		d.Version == 0 && d.Checksum == nil && len(d.Sources) == 0
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
	if d.Checksum != nil {
		checksum := *d.Checksum
		clone.Checksum = &checksum
	}
	if len(d.Sources) > 0 {
		clone.Sources = make([]DocumentSource, 0, len(d.Sources))
		for _, source := range d.Sources {
			clone.Sources = append(clone.Sources, source.Clone())
		}
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

	// Through the named classes, so a fix to a class reaches every field in
	// it rather than this one copy. Both sides were gated above, so the
	// per-item publishability tests here are nil.
	merged := left
	merged.Name = MergeFillGap(left.Name, right.Name, nil)
	merged.DataLicense = MergeFillGap(left.DataLicense, right.DataLicense, nil)
	merged.Created = MergeFillGap(left.Created, right.Created, nil)
	merged.Comment = MergeFillGap(left.Comment, right.Comment, nil)
	// Identity, Version, and Checksum are one provenance tuple: the link
	// forms pair them, and a checksum is a claim about one document's bytes.
	// Filling each independently let a record identifying document A take
	// document B's version and digest, so an SPDX external-document
	// reference could claim A's bytes have B's checksum. The tuple fills as
	// a unit: a side that states no link at all takes the other's whole
	// tuple; the same document seen twice fills its own gaps; two different
	// documents keep the first one's tuple, and the second's version and
	// checksum go nowhere rather than onto the wrong identity.
	//
	// "The same document" is sameDocumentLink: the same identity at a
	// compatible version.
	leftHasLink := left.Identity != "" || left.Version != 0 || left.Checksum != nil
	switch {
	case !leftHasLink:
		merged.Identity, merged.Version, merged.Checksum = right.Identity, right.Version, right.Checksum
	case sameDocumentLink(left.Identity, left.Version, right.Identity, right.Version):
		merged.Version = MergeFillGap(left.Version, right.Version, nil)
		merged.Checksum = MergeFillGap(left.Checksum, right.Checksum, nil)
	}
	// Cloned, so the merged record does not alias either input.
	if merged.Checksum != nil {
		checksum := *merged.Checksum
		merged.Checksum = &checksum
	}
	merged.Creators = MergeUnion(left.Creators, right.Creators, creatorKey, nil)
	merged.Tools = MergeUnion(left.Tools, right.Tools, toolKey, nil)
	// Sources union by document, which is what the gate does when it folds
	// entries naming the same document: the union is left's list followed by
	// right's, passed through the gate again so the merged record's own
	// identity drops from among the other side's sources, folds fill gaps,
	// and the bound holds -- left's entries first, so they are the ones a
	// bound keeps. Sorted by the gate, so merge order does not change the
	// bytes of what survives.
	merged.Sources = append(append([]DocumentSource(nil), left.Sources...), right.Sources...)
	merged, _ = merged.Normalized()
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
