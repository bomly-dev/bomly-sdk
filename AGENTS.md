# AGENTS.md

Guidance for coding agents working in this repository. `CLAUDE.md` is an
identical copy; keep the two files in sync.

This module, `github.com/bomly-dev/bomly-sdk`, is the public contract for the
Bomly CLI (`bomly-dev/bomly-cli`), its built-in components, and external
managed plugins: domain types (the `GraphNode` union — manifest, module,
and `DependencyNode` records — `Package`, `Vulnerability`, `Finding`,
`Graph`), plugin kinds and validation, support metadata, and the
shared helper subpackages (`system`, `filecache`, `logkit`, `detectorkit`,
`matcherkit`, `testkit`, `conformance`).

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

`ScopesFromCycloneDX` in `scope_cyclonedx.go` is the worked example: the SDK
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
`scope_filter.go`: a filter selects on assertions, absence is not an
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
the optional ceiling. `RootAttribution` and `NewRootAttributor` in `usage.go`
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
  be optional and tagged `omitempty` (`TestWireV1NewFieldsAreOmitEmpty`
  guards this for the payloads and fields it enumerates — extend its
  enumeration when adding wire surface; a field outside it is not covered);
  frozen fixtures must keep decoding
  (`TestWireV1FixturesDecode` — never "fix" a fixture); fields and RPCs are
  never removed, renamed, or repurposed within v1. A breaking change ships
  as `bomly.plugin.v2` negotiated alongside v1.

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
