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

## Build & test

```sh
go test ./...    # all tests must pass before work is done
go vet ./...
gofmt -l .          # CI gates on formatting
go mod tidy -diff   # CI gates on go.mod/go.sum tidiness
```

The `conformance` package is the reusable plugin-contract suite; changes to
descriptors, validation, or the serve surface must keep it green, and the
CLI's `TestExamplePluginFixtureCompiles` compiles against the released SDK —
breaking the pinned contract there means the change needs a release-notes
callout and a coordinated bump.
