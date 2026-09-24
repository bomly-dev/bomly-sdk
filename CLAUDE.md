# CLAUDE.md

Guidance for coding agents working in this repository. `CLAUDE.md` is an
identical copy; keep the two files in sync.

This module, `github.com/bomly-dev/bomly-sdk`, is the public contract for the
Bomly CLI (`bomly-dev/bomly-cli`), its built-in components, and external
managed plugins. It is four packages, split by the question each answers:
`model` (what the data is: the `GraphNode` union — manifest, module, and
`DependencyNode` records — `Package`, `Vulnerability`, `Finding`, `Graph`,
the vocabularies, and the normalization, merge, and policy rules), `plugin`
(what a component is: the role interfaces, descriptors, request/response
types, `Module`/`HostContext`, validation), `runtime` (how a component runs
out of process: the go-plugin gRPC transport, both ends), and `httpkit`
(outbound HTTP policy). The module root declares nothing but the map. Around
them sit the helper subpackages (`purlkit`, `spdxkit`, `system`, `filecache`,
`logkit`, `detectorkit`, `matcherkit`, `testkit`, `conformance`), the SBOM
codec (`sbom`, with `graphview` beside it), which the CLI and the Syft and
Grype plugins adopt from the release that carries it in place of the copies
they carried (bomly-cli ADR-0045), and the scan record (`scan`): the
document `bomly scan --json` emits, versioned as `bomly.scan.v1`.

## This module is the source of truth

The standing placement rule (recorded as
[ADR-0040 in bomly-cli](https://github.com/bomly-dev/bomly-cli/blob/main/dev-docs/adr/0040-the-sdk-is-the-default-home-for-behavior.md),
landing via [bomly-dev/bomly-cli#411](https://github.com/bomly-dev/bomly-cli/pull/411) —
the link resolves once that PR merges):
behavior about shared domain objects — identity, coordinates, PURLs,
licenses, SBOM assertions, graph and merge semantics, validation gates —
lands **here first**, and the CLI and plugins consume it. When a bug is
reported against the CLI but the rule it violates is a model rule, the
durable fix belongs in this module; a CLI-side patch is a loan, taken only
with the SDK issue already filed and linked.

The inverse holds too: do not admit consumer-specific behavior. CLI
presentation, command surfaces, and pipeline orchestration stay in
`bomly-cli`; one external tool's integration specifics stay in its
`bomly-plugin-*` repository. The test is ownership by nature, not current
usage — "only one consumer needs this today" is neither a reason to keep it
out nor a reason to let it in.

Bomly's architecture decisions live in
[`bomly-cli/dev-docs/adr/`](https://github.com/bomly-dev/bomly-cli/tree/main/dev-docs/adr);
decisions that shape this module's surface are recorded there even when the
code lands here.

### A specification outranks anything Bomly wrote

Being the source of truth for Bomly's behavior is not being the source of
truth for what someone else's format means. When a format's specification and
a Bomly document disagree about the meaning of a value that format defines,
**the specification wins, in every case, without being weighed against
anything.** A Bomly document is an ADR — accepted ones included — a doc
comment, a test that pins shipped behavior, a review conclusion, or an issue's
framing of the merits. None of them is evidence about CycloneDX, SPDX, PURL,
or SemVer, because Bomly never got to decide what a word means in a format it
does not own.

So an issue that turns on what a format's value means is resolved by a
citation, not by an argument. Read the specification first — preferably as the
pinned dependency vendors it, since `cyclonedx-go` ships the CycloneDX JSON
schemas with their normative `meta:enum` descriptions and `spdx/tools-golang`
its own vocabularies — quote it in the code next to the behavior it settles,
and then correct whichever Bomly document was wrong. Correcting an accepted
ADR is the expected outcome, not an escalation.

Two arguments in particular do not survive this rule. That producers in the
wild spell a value loosely is not a reason to read the vocabulary loosely: it
would mean reading every conforming document wrongly to accommodate the ones
that are not. And "this direction is safer for a scanner" does not license a
non-conforming reading either — a safety concern is answered by a warning, a
Bomly-owned policy knob that says plainly that it departs from the
specification and why, or an upstream bug report against the producer, never
by quietly redefining the format's word. Where a specification genuinely says
nothing, the mapping onto Bomly's own vocabulary is Bomly's policy, and it is
documented as policy rather than dressed up as the format's meaning.

`ScopesFromCycloneDX` in `model/scope_cyclonedx.go` is the worked example: the SDK
read CycloneDX's `optional` as runtime on a pre-1.6 gloss, argued it was the
safer reading for a scanner, and was wrong on both counts against the
specification's own text. Reading that text also turned up a second deviation
nobody had argued about at all — an absent scope, which CycloneDX says a
consumer should assume is `required`, was read as no scope and dropped from
every runtime filter (issue #63).

### Reading a node of any kind

`GraphNode` exposes only what every kind has: an ID, a kind, locations,
warnings, a clone. Coordinates, a display name, a scope belong to some kinds
and not others, so a consumer that renders or narrows a node reaches for
`NodeCoordinates`, `NodeDisplayName`, `NodeVersion`, `NodePURL`,
`AsDependencyNode`, `AsModuleNode`, `DependencyNodesOf`, `IsProjectOwned`,
or `IsNilNode` rather than writing its own type switch. `NodePURL` is the
one a consumer is most tempted to answer with `NodeID()`, which is right
for a dependency and wrong for the other two kinds. Written per consumer, that switch
disagrees with itself about what a manifest looks like -- the CLI grew four
such copies in one release before these existed.

`IsNilNode` is the one that is easy to skip and expensive to skip: a typed
nil is not an untyped one, so `node != nil` is true for a
`(*DependencyNode)(nil)` and the next field read panics.

The same rule covers the vocabulary joins between a package URL and the
domain types. `PackageURLTypeForValues` maps ecosystem, package manager,
and package type to a purl type; `EcosystemForPURLType` maps the type back
to an `Ecosystem`, refusing the ambiguous ones (`pkg:hex` serves Elixir and
Erlang alike) rather than guessing. Both are spec-derived tables, so a
transcription is stale the day the vocabulary grows -- the CLI's three
copies of the reverse join had already drifted when this was exported.

### Narrowing by scope

Never compare a scope by hand. `ScopeSetMatches` and `MatchesScopeFilter` are
the answer, because the hard case is not comparison but a dependency that
asserted no scope at all — and that case has a policy, stated in
`model/scope_filter.go`: a filter selects on assertions, absence is not an
assertion, so a runtime view keeps everything not affirmatively
development-only — a set naming both scopes names runtime, so it stays —
while every other view requires an affirmative match. One rule, applied
twice: an unasserted scope resolves toward "may be in production", the only
direction that cannot hide a finding.

Getting it wrong is quiet and expensive. `Scopes` is a union across
declaration sites, so `containsScope(node.Scopes, ScopeDevelopment)` puts a
package that also ships into the list a user reads as safe to deprioritize;
and matching the effective scope exactly drops every package in a third-party
SPDX document from a runtime view, because SPDX has no scope concept and each
package arrives unscoped. Both readings were shipped. A filter that keeps
nodes on absence should also report how many, the way
`FilterGraphByScopeWithReport` does — a runtime view that narrowed nothing
must not look narrowed.

### Attributing evidence to a module root

`ReachabilityEvidence` is keyed by module root, so an analyzer must decide
whether a dependency node's sites tie it to the root it is emitting for --
the module root is the mandatory floor of that claim and `DependencyRefs`
the optional ceiling. `RootAttribution` and `NewRootAttributor` in `model/usage.go`
own the decision, including the self-calibration that keeps a
producer/analyzer path-vocabulary mismatch from silently dropping a node's
evidence. This landed as four identical copies across the reachability
analyzer repositories first; an analyzer that writes its own gets the easy
half right and the calibration wrong.

## Compatibility contract

Two axes, with different rules (see `README.md` for the full policy):

- **In-process Go API** — the module is v0: minor releases may adjust the
  API; patch releases are always safe. Consumers embed `Base*` structs to
  stay insulated from interface growth.
- **Wire (`bomly.plugin.v1`)** — strictly additive, forever. Payloads are
  JSON over gRPC, so struct JSON tags *are* the wire schema. New fields must
  be optional and tagged `omitempty` (`TestWireV1TaggedFieldsDeclareOmitEmpty`
  walks every type reachable from the wire roots and enforces it;
  `TestWireV1NewFieldsAreOmitEmpty` additionally pins the zero-value keys of
  the payloads and fields it enumerates — extend its enumeration when adding
  wire surface);
  frozen fixtures must keep decoding
  (`TestWireV1FixturesDecode` — never "fix" a fixture); fields and RPCs are
  never removed, renamed, or repurposed within v1. A breaking change ships
  as `bomly.plugin.v2` negotiated alongside v1.
- **Scan record (`bomly.scan.v1`)** — the document `scan.Encode` writes:
  additive within v1, `schema_version` names it, `scan.Decode` refuses
  another. `scan/record_test.go` is its own omitempty guard, because the
  plugin walk stops at `plugin` and `model`. Nothing in `scan` moves a
  record anywhere; how one travels is not this module's to decide.

Release ordering: **this module tags first, plugin repositories adopt the new
tag, then bomly-cli updates its pin.** Never ask consumers to pin a commit or
branch.

## Conventions

- Every exported type and function has a doc comment. New model fields name
  their validation gate and merge class (fill-gaps scalar, union set, or
  contradiction-preserving) in the doc comment.
- Validation lives with the type: fields carrying untrusted input normalize
  in their JSON codecs on both marshal and unmarshal, the way
  `DependencyOrigin` does, so no call site can bypass the gate.
- Every parser of untrusted input ships with a native Go fuzz target from
  its first commit; bound input size before parsing.
- Errors wrap with context (`fmt.Errorf("...: %w", err)`); no panics in
  normal flow — contain third-party panics at the boundary instead.
- Loggers may be nil; nil-check or use `zap.NewNop()`. No secrets or
  credentials in logs, ever.
- Standard library plus the existing pinned dependencies only; discuss
  before adding any dependency.
- Kits are adapters around established libraries, not replacement
  implementations: go-spdx owns what an SPDX expression means, validates
  as, and normalizes to; packageurl-go owns PURL parsing and rendering;
  go-pep440-version owns what a PyPI version is and how it canonicalizes.
  When review proposes sharpening a hand-written heuristic, replace it
  with library delegation instead — and keep unavoidable resource bounds
  dumb (bytes and counts), frozen once pinned. Delegate grammar parsing, validation, normalization,
  canonical rendering, and semantic algorithms to the owning dependency.
  Custom kit code is limited to Bomly policy and mappings, safety containment
  and work limits, consumer adapters, and verified gaps in the dependency. Do
  not mirror a dependency's tokenizer, AST, normalizer, or renderer merely to
  preserve lexical formatting or accommodate edge syntax it already accepts.
- When a dependency lacks a required capability, first use its public
  normalized or structured output if possible; otherwise evaluate an upstream
  fix or a mature alternative before writing a bespoke parser or semantic
  algorithm. Any unavoidable custom implementation documents why the upstream
  path is insufficient and ships differential or fixture tests plus fuzzing.

### Layout

Four packages carry the contract, and the dependency direction between them
is fixed: `runtime` imports `plugin`, `plugin` imports `model`, `model`
imports only `purlkit`, `spdxkit`, the standard library, and the two format
libraries whose vocabularies it cites by constant (cyclonedx-go,
spdx/tools-golang); `httpkit` is a leaf that `plugin` reaches for
`HostContext`; `scan` imports `model`, `plugin` and `graphview`, and nothing
imports `scan`. Nothing imports upward. The
module root holds `doc.go` (the map) and `repo_guards_test.go` (the import
boundary and the AGENTS.md/CLAUDE.md mirror, both keyed on the root
directory) and nothing else; do not add code there.

Within a package a file is named for the concept it owns, and a test file
pairs with the source file of the same stem (`contact.go` /
`contact_test.go`); add to the owner rather than starting a new file for a
type that already has a home. What lives where:

- `model/` — graph core: `node.go`, `node_access.go`, `dependency.go`,
  `coordinates.go`, `graph.go`, `edge.go`, `relationship.go`,
  `container.go`; packages and enrichment: `package.go`, `registry.go`,
  `vulnerability.go`, `vulnerability_analysis.go` (VEX impact analysis,
  citing cyclonedx-go's constants), `assertions.go` (the component-level
  claims `DependencyNode` and `Package` embed), `usage.go`,
  `attestation.go`, `scorecard.go`, `metadata.go`; format vocabularies:
  `contact.go`, `digest.go`, `external_reference.go`, `document.go`,
  `origin.go`; vocabularies and
  identity: `ecosystem.go`, `package_manager.go`, `language.go`, `purl.go`,
  `normalization.go`; wire codecs and adapters: `json.go`,
  `scope_cyclonedx.go`; merge and policy: `merge.go`, `policy.go`,
  `scope_filter.go`. Guards with no source pair: `vocabulary_registry_test.go`,
  `purlkit_delegation_test.go`, `provenance_test.go`, `idn_test.go`,
  `wire_codec_coverage_test.go` (the unexported codec structs), and
  `fuzz_test.go` (every model `Fuzz*` target; corpora under
  `model/testdata/fuzz/<Name>/`). Shared fixture constructors live in
  `helpers_test.go`.
- `plugin/` — `component.go` (descriptors, the `Base*` defaults, the
  `Validate*Descriptor` gates), `detector.go`, `matcher.go`, `auditor.go`,
  `analyzer.go`, `scan.go` (execution targets and subprojects), `module.go`,
  `plugin.go` (manifest and wire vocabulary), `config_schema.go`,
  `consolidation.go` (the host's consolidated view), `detection_filter.go`
  (scope filtering of a detection result). Guards: `wire_compat_test.go`
  (frozen v1 fixtures) and `wire_omitempty_coverage_test.go`, whose walk
  starts at the wire roots here and follows exported fields into `model`.
- `runtime/` — `serve.go` (the bomly.plugin.v1 service, both ends),
  `module.go` (`ServeModule` and the managed `HostContext`), `config.go`
  (the per-process environment). `boundary_test.go` fails on any json-tagged
  struct here: the transport carries payloads and declares none.
- `httpkit/` — `client.go`, `proxy.go`.
- `scan/` — `record.go` (the record and its sections, `SchemaVersion`),
  `encode.go` (`Encode`, `Decode`, `Digest`, the bounds), `build.go`
  (`FromGraphEntries`, `VerdictOf`), `compare.go`. Guard: `record_test.go`
  (every struct reachable from `Record` declares omitempty or omitzero).

The managed-plugin transport (go-plugin, gRPC, protobuf) lives only in
`runtime/`; `repo_guards_test.go` fails an import of those libraries anywhere
else, with one named exception: `conformance/` imports go-plugin to launch a
built plugin binary over the real transport (`ProbeBinary`), exactly as the
host does. Every wire payload type lives in `model` or `plugin`, where the
omitempty coverage walk can see it.

### The modernizer, and the analyzers we decline

`go fix ./...` is the Go 1.27 modernizer. It **applies** its rewrites in place;
`go fix -diff ./...` prints them instead, which is how to look first.

Two of its analyzers are declined here. Run it as:

```sh
go fix -embedlit=false -omitzero=false ./...
```

- **`embedlit`** flattens `Coordinates: Coordinates{...}` into the bare
  promoted fields at construction sites. It is behaviour-identical and
  `gorelease` is indifferent, so nothing mechanical will object -- which is the
  reason to write the decision down. Coordinates is a named identity concept
  (ADR-0041), and the wrapper at a construction site is what makes the identity
  visible where a package is built. That argument is strongest in this module,
  because this is where identity is defined. bomly-cli declines it too, and the
  two must keep agreeing: they disagreed once, and reverting cost 43 hunks.
- **`omitzero`** drops `omitempty` from struct-valued JSON fields. The encoded
  bytes do not move -- `encoding/json` never omits a struct -- so no test and
  no API gate objects. But the tag *is* the wire schema for `bomly.plugin.v1`
  (see the compatibility contract above), and a consumer generating a schema by
  reflection then reads the field as required. This pass took that rewrite and
  it cost four review rounds to undo; the markers it would delete are back on
  `MatchResult.MatcherStats`, `PackageScorecard.RunDate` and
  `CallFrame.Position`, and `go fix ./...` unqualified deletes them again.

Neither is caught by a test, a linter or the API gate, which is exactly why the
list lives here.
## Build & test

```sh
make test          # go test ./... — all tests must pass before work is done
make vet           # go vet ./...
make fmt-check     # CI gates on gofmt formatting (make fmt rewrites)
make lint          # golangci-lint, pinned in the Makefile and ci.yml
make tidy-check    # go mod tidy -diff — CI gates on go.mod/go.sum tidiness
make fuzz FUZZTIME=5s   # every Fuzz* target briefly; nightly in CI at 2m each
make install-hooks # pre-commit runs fmt-check and lint
```

CI also forbids `replace` directives in `go.mod` (a library must resolve the
same way for every consumer) and diffs the exported API against the latest
release tag with gorelease; a deliberate v0 break needs the
`api:break-approved` label. Fuzz targets are discovered by
`scripts/run-fuzz.sh`, not listed, so a new `Fuzz*` function is picked up
by the nightly run without registration. Dependabot (Go modules and
Actions, weekly, grouped), Dependency Review, OpenSSF Scorecard, and Bomly
Guard run as separate workflows under `.github/workflows/`. CodeQL runs
through GitHub's default code-scanning setup (Go and Actions), which is a
repository setting rather than a workflow file; GitHub rejects an advanced
CodeQL workflow while default setup is enabled, so do not add one.

Where a specification's rules have no library that owns them, the
specification's own machine-readable documents are vendored and diffed
against, rather than trusted to a transcription that was right when it was
written: `purlkit/testdata/purl-spec/` holds the purl type definitions
verbatim (refresh with `scripts/vendor-purl-spec.sh <sha>`), and
`TestTypeProfilesMatchSpecification` fails on any difference the
`specDeviations` map does not name and justify. A deliberate departure from
a specification lives in that map, never as an unexplained table row.

The `conformance` package is the reusable plugin-contract suite; changes to
descriptors, validation, or the serve surface must keep it green, and the
CLI's `TestExamplePluginFixtureCompiles` compiles against the released SDK —
breaking the pinned contract there means the change needs a release-notes
callout and a coordinated bump.
