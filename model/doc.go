// Package model is Bomly's domain model: the dependency graph and its node
// kinds, package records and the PURL-keyed registry, vulnerabilities and
// findings, the controlled vocabularies (ecosystems, package managers,
// languages, scopes), and the normalization, merge, and policy rules that
// every producer and consumer of those values shares.
//
// The central types deliberately separate pipeline stages. DependencyNode is a
// detection-time graph node with identity, locations, scopes, and edges.
// PackageRegistry is a PURL-keyed set of deduplicated Package records that
// matchers enrich once per package version. Vulnerability records are
// OSV-aligned package enrichment data, including Bomly fields such as CVSS,
// EPSS, KEV, fixed versions, affected symbols, and reachability. Finding is a
// reference-style audit result: it points back to packages by PURL and, for
// vulnerability findings, to Vulnerability.ID rather than copying the whole
// package or advisory payload.
//
// Coordinates is the shared embedded identity shape used by DependencyNode and
// Package. Prefer canonical PURLs, fill Coordinates where possible, and use
// typed values such as Ecosystem, PackageManager, PackageType, Scope, and
// SeverityLevel instead of raw strings. PackageManager is string-backed for
// compatibility; use PackageManagerOther or a custom PackageManager value when
// Bomly does not yet have a first-class constant for a package manager.
//
// Node identity is derived, never hand-assembled (ADR-0041): the
// constructors are the only mint -- a dependency node's ID is its canonical
// package URL (custom purl types are first-class; express any ecosystem as
// a purl type), and module and manifest nodes carry kind-qualified
// canonical paths. Never build a node ID by string concatenation.
//
// Attribution is per site, not per package. A package's scope and
// directness belong to the location it was found at: in a workspace the same
// version is a direct development dependency of one module and a transitive
// runtime dependency of another, so a node's unions answer neither question.
// PackageLocation carries the module root, scopes, and relationship;
// reachability is per-module-root evidence with the vulnerability annotation
// as the derived summary; and SelectUsages joins the two within one module
// root so a conjunctive question is a statement about a usage that exists.
// Read scopes through AttributedScopes rather than the node field.
//
// Merges are classed rather than hand-written. MergeFillGap, MergeUnion, and
// MergeStrongest name the three rules every field in this model follows, and
// each field declares which class it is in. A merge written by hand is where
// this model has repeatedly lost data -- a first-wins rule dropping a better
// value, an early return leaving an ungated claim visible, an unsorted result
// making a document's bytes depend on read order -- so fixing a class is
// preferred to fixing a field.
//
// Metadata maps carry what the typed fields do not, and the "bomly." prefix is
// reserved for this project (IsReservedMetadataKey). A value that lives only
// in a metadata map is invisible to every gate -- not normalized, not
// validated, not merged by a declared rule, not projected to either document
// format -- so anything a typed field can hold belongs in the typed field.
//
// Every value here is also a wire value: these structs are the JSON payloads
// of the bomly.plugin.v1 protocol, so their tags are the wire schema and
// grow only additively. The component contract that carries them lives in
// the plugin package; the managed transport in the runtime package.
package model
