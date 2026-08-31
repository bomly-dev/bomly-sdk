// Package sdk is Bomly's public Go contract for dependency graphs, package
// enrichment, policy findings, and managed external plugins.
//
// Most external developers use this package to build a managed plugin. Managed
// plugins are native Go binaries that Bomly launches as separate subprocesses
// over the HashiCorp go-plugin gRPC transport. A plugin implements exactly one
// externally supported role:
//
//   - detector: reads project evidence and returns dependency graphs
//   - matcher: enriches PURL-keyed package records with vulnerability, license,
//     lifecycle, or other package metadata
//   - auditor: evaluates graph and registry data and emits findings or risk
//     scores
//   - analyzer: runs code analysis (e.g. reachability) over the matched graph
//     and annotates registry vulnerability entries
//
// A plugin binary serves its role from main by calling one of the runtime
// entrypoints:
//
//	func main() {
//		sdk.ServeDetector(&detector{})
//	}
//
// The corresponding plugin-facing interfaces are ServedDetector, ServedMatcher,
// ServedAuditor, and ServedAnalyzer. They use the same request and response
// types as Bomly core: DetectionRequest and DetectionResult for detectors,
// MatchRequest and MatchResult for matchers, AuditRequest and AuditResult for
// auditors, and AnalyzeRequest and AnalyzeResult for analyzers.
//
// The central data model deliberately separates pipeline stages. Dependency is
// a detection-time graph node with identity, locations, scopes, and edges.
// PackageRegistry is a PURL-keyed set of deduplicated Package records that
// matchers enrich once per package version. Vulnerability records are
// OSV-aligned package enrichment data, including Bomly fields such as CVSS,
// EPSS, KEV, fixed versions, affected symbols, and reachability. Finding is a
// reference-style audit result: it points back to packages by PURL and, for
// vulnerability findings, to Vulnerability.ID rather than copying the whole
// package or advisory payload.
//
// Coordinates is the shared embedded identity shape used by Dependency and
// Package. Plugin authors should prefer canonical PURLs, fill Coordinates where
// possible, and use typed values such as Ecosystem, PackageManager,
// PackageType, Scope, and SeverityLevel instead of raw strings. PackageManager
// is string-backed for compatibility; use PackageManagerOther or a custom
// PackageManager value when Bomly does not yet have a first-class constant for
// a package manager.
//
// Node identity is derived, never hand-assembled (ADR-0041): the
// constructors are the only mint — a dependency node's ID is its canonical
// package URL (custom purl types are first-class; express any ecosystem as
// a purl type), and module and manifest nodes carry kind-qualified
// canonical paths. Never build a node ID by string concatenation.
//
// Plugin identity is split across package metadata and runtime metadata. The
// bomly-plugin.json manifest describes packaging and install fields such as ID,
// version, kind, runtime, plugin API version, entrypoint, homepage, and license.
// The runtime descriptor returned by Descriptor describes the served component:
// name, display name, aliases, tags, supported ecosystems, supported package
// managers, and role-specific behavior. Bomly verifies that manifest identity
// and runtime descriptor identity match when a packaged plugin is installed, and
// records installed trust state separately.
//
// Attribution is per site, not per package (phase 1.4). A package's scope and
// directness belong to the location it was found at: in a workspace the same
// version is a direct development dependency of one module and a transitive
// runtime dependency of another, so a node's unions answer neither question.
// PackageLocation carries the module root, scopes, and relationship;
// reachability is per-module-root evidence with the vulnerability annotation
// as the derived summary; and SelectUsages joins the two within one module
// root so a conjunctive question is a statement about a usage that exists.
// Read scopes through AttributedScopes rather than the node field, and expect
// both to be empty until the producers migrate.
//
// Merges are classed rather than hand-written. MergeFillGap, MergeUnion, and
// MergeStrongest name the three rules every field in this model follows, and
// each field declares which class it is in. A merge written by hand is where
// this model has repeatedly lost data — a first-wins rule dropping a better
// value, an early return leaving an ungated claim visible, an unsorted result
// making a document's bytes depend on read order — so fixing a class is
// preferred to fixing a field.
//
// Metadata maps carry what the typed fields do not, and the "bomly." prefix is
// reserved for this project (IsReservedMetadataKey). A value that lives only
// in a metadata map is invisible to every gate — not normalized, not
// validated, not merged by a declared rule, not projected to either document
// format — so anything a typed field can hold belongs in the typed field.
//
// Plugins that need configuration should read only their per-plugin config with
// DecodePluginConfigFromEnv. Plugins that make HTTP calls should create a
// process-local provider with NewHTTPClientProviderFromEnv so Bomly's proxy,
// no-proxy, and CA certificate settings are honored consistently.
//
// The repository documentation contains the workflow-oriented guides for
// packaging, installing, testing, and distributing plugins. This package
// documentation is the API-oriented reference for the types those guides use.
package sdk
