# Bomly SDK

<p align="center">
  <a href="https://github.com/bomly-dev/bomly-sdk/actions/workflows/ci.yml"><img src="https://github.com/bomly-dev/bomly-sdk/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/bomly-dev/bomly-sdk"><img src="https://api.scorecard.dev/projects/github.com/bomly-dev/bomly-sdk/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://github.com/bomly-dev/bomly-sdk/releases/latest"><img src="https://img.shields.io/github/v/release/bomly-dev/bomly-sdk?sort=semver" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/bomly-dev/bomly-sdk" alt="License: Apache-2.0"></a>
  <a href="https://pkg.go.dev/github.com/bomly-dev/bomly-sdk"><img src="https://pkg.go.dev/badge/github.com/bomly-dev/bomly-sdk.svg" alt="Go Reference"></a>
</p>

`github.com/bomly-dev/bomly-sdk` is the contract module for building Bomly
components: detectors, matchers, auditors, and analyzers. It is four packages,
split by the question each answers:

| Package | Answers | Import it when |
|---|---|---|
| `model` | What the data is: the dependency graph, packages and the registry, vulnerabilities and findings, the vocabularies, and the normalization, merge, and policy rules they share. | Always; every component reads and returns these. |
| `plugin` | What a component is: the `Detector`, `Matcher`, `Auditor`, and `Analyzer` interfaces, their descriptors and request/response types, the `Base*` defaults, and `Module`/`HostContext`. | Implementing a component, embedded or as a plugin. |
| `runtime` | How a component runs out of process: `ServeModule` for a plugin binary's `main`, and `Client`/`HandshakeConfig`/`ClientPluginMap` for the host that launches it, over the go-plugin gRPC transport. | A plugin binary's `main`, or hosting plugins. |
| `httpkit` | Outbound HTTP with Bomly's proxy and CA policy. | Rarely directly; a component gets it from `HostContext.HTTPClient()`. |

The module root imports nothing and declares nothing; its package doc is
this map.

```sh
go get github.com/bomly-dev/bomly-sdk@latest
```

## Building a plugin

A Bomly plugin is a component packaged as a `plugin.Module` and served from
`main` by the runtime:

```go
package main

import (
	"github.com/bomly-dev/bomly-sdk/plugin"
	"github.com/bomly-dev/bomly-sdk/runtime"
)

func main() {
	runtime.ServeModule(plugin.Module{
		Kind:     plugin.PluginKindDetector,
		Detector: &plugin.DetectorModule{Descriptor: descriptor, Support: support, New: newDetector},
	})
}
```

The same `Module` value registers embedded in the host; a component never
learns which mode it runs in, because it reaches the host only through
`plugin.HostContext`. See the
[Bomly plugin documentation](https://github.com/bomly-dev/bomly-cli/blob/main/docs/PLUGINS.md)
for the full authoring guide, packaging layout (`bomly-plugin.json`), and
installation flow.

Embed the `Base*` types (`plugin.BaseDetector`, `plugin.BaseMatcher`,
`plugin.BaseAuditor`, `plugin.BaseAnalyzer`) in your implementation so future
additions to the component interfaces do not break your build.

## Helper packages

The SDK ships shared helper subpackages so component modules and external
plugins reuse the same implementations Bomly's built-ins use:

- `system` — bounded filesystem reads plus exec, path, and environment wrappers.
- `filecache` — TTL-based on-disk JSON cache with typed `Get`/`Set` helpers.
- `logkit` — secret-safe subprocess logging: argument/URL sanitizers, command fields, stderr counter.
- `detectorkit` — detector helpers: manifest metadata, source positions, remediation hints, subgraphs, build-tool readiness and timeouts.
- `matcherkit` — matcher helpers: registry package seeding and license normalization.
- `testkit` — test helpers: fuzz graph invariants, typed-node constructors, Go binary builders, lockfile position assertions.
- `purlkit` — the single home for package-URL behavior: parsing, building, canonicalizing, the purl-type mapping table, and the per-ecosystem name split, over packageurl-go and go-pep440-version.
- `spdxkit` — the single home for SPDX license behavior: expression validation, classification, deprecated-identifier canonicalization, and deterministic `LicenseRef` minting, containing go-spdx's panics on untrusted input.
- `conformance` — the reusable plugin-contract test suite: run it against your `plugin.Module` for descriptor validity, JSON round-trip stability, host-context construction, the Ready/Applicable lifecycle, role capabilities, and optionally a transport probe of the built binary.

Within each package a file is named for the concept it owns and every test
file pairs with the source file of the same stem; `AGENTS.md` carries the map.

## Migrating to v0.13

v0.13.0 dissolved the root package into `model`, `plugin`, and `runtime`,
and moved the HTTP client provider to `httpkit`. The wire protocol is
unchanged; every identifier keeps its name and moves to the package that
owns it:

| Before (`sdk.`) | After |
|---|---|
| Graph, node, package, registry, vulnerability, finding, vocabulary, scope, origin, digest, contact, document, normalization, merge, and policy types and functions | `model.` (same names) |
| `Detector`, `Matcher`, `Auditor`, `Analyzer`, `Base*`, `*Descriptor`, `*Request`/`*Result`/`*Response`, `Module`, `*Module`, `HostContext`, `RuntimeInfo`, `Validate*`, `ConfigSchemaFor`, `PluginKind*`, `Consolidated*`, `ExecutionTarget`, `Subproject`, `FilterDetectionResultByScope` | `plugin.` (same names) |
| `ServeModule`, `Serve*`, `Served*`, `Client`, `HandshakeConfig`, `ClientPluginMap`, `EnvVerbosity`, `EnvPluginConfigFile`, `EnvPluginID`, `RawPluginConfigFromEnv`, `DecodePluginConfigFromEnv` | `runtime.` (same names) |
| `HTTPClientProvider`, `HTTPClientConfig`, `NewHTTPClientProvider`, `NewHTTPClientProviderFromEnv`, `HTTPClientConfigFromEnv`, `NewHTTPClient`, `EnvHTTP*` | `httpkit.ClientProvider`, `httpkit.ClientConfig`, `httpkit.NewClientProvider`, `httpkit.NewClientProviderFromEnv`, `httpkit.ClientConfigFromEnv`, `httpkit.NewClient`, `httpkit.EnvHTTP*` |

Two spellings changed besides the package: `containsControlChar` is now
`model.ContainsControlChar`, and the component-name bound is
`model.MaxComponentNameLength`. `HostContext.HTTPClient()` returns
`*httpkit.ClientProvider`. A file that already imported the root as `model`
changes only its import path. A consumer package named `plugin` imports
`github.com/bomly-dev/bomly-sdk/plugin` under an alias, or renames itself.

## Migrating to v0.14

v0.14.0 lifts the nine component-level assertions `model.DependencyNode` and
`model.Package` both carried — `Description`, `Homepage`, `Supplier`,
`Originator`, `ExternalReferences`, `CPEs`, `Digests`, `Licenses`,
`Copyright` — into one embedded `model.Assertions`. Reads, writes and
composite literals naming those fields compile unchanged through promotion;
JSON is unchanged. What changes is the Go API surface (the fields moved), so
the release is a v0 minor. `Graph` JSON now lists `nodes` by node ID and
`edges` by `(fromId, toId)`, and graph and registry decoding refuse payloads
over `model.MaxPayloadBytes`, `MaxGraphNodes`, `MaxGraphEdges` and
`MaxRegistryPackages`.

## The scan record

- `scan` — the scan record: `scan.Record`, the document `bomly scan --json` emits, with its manifests, packages and findings, and what that output never said about itself — the subject, the run, the verdict, the policy and waivers, and a digest per section. `Encode` is byte-stable, `Decode` is bounded and refuses another schema, `FromGraphEntries` builds one from a pipeline's entries, registry and findings, and `Compare` reports the dependency, advisory and finding deltas between two.

A record relates to an SBOM in both directions: its manifests are what the
codec below projects into a document and reads back, so an SBOM is derivable
from a record, and a scan that ingested an SBOM yields a record whose manifest
carries that document's own assertions. Its packages and findings hold what
an SBOM cannot say.

## The SBOM codec

- `sbom` — the SBOM codec: projects a graph into SPDX 2.3 or CycloneDX JSON and reads such a document back into a graph, with the document model, the strict ingest preflight, and the assertions a document carries about itself.
- `graphview` — what a document may say about a node: the package URL it publishes, which of its children a document can name, and which nodes count as top-level parents.

Both come from the CLI's `internal/sbom` and `internal/graphview`
(bomly-cli ADR-0045). The CLI and the Syft and Grype plugins adopt this
package from the release that carries it, in that order -- the plugins
first, then the CLI, which pins both -- and delete their copies as they do.

## Compatibility

Three independent compatibility axes govern this module:

1. **In-process (Go API)** — the component interfaces and types consumed by
   embedders. Signature changes require a recompile. Embedding the `Base*`
   defaults insulates implementations from most interface growth.
2. **Wire (managed-plugin protocol `bomly.plugin.v1`)** — JSON payloads
   exchanged with external plugin binaries. Within protocol v1, changes are
   strictly additive: new optional (`omitempty`) fields and new optional RPCs
   only. Hosts treat unimplemented RPCs as feature fall-backs; unknown JSON
   fields are ignored by both sides. Fields and RPCs are never removed,
   renamed, or repurposed within v1. A breaking wire change would ship as a
   new `bomly.plugin.v2` service negotiated alongside v1 — old binaries keep
   speaking v1.
3. **Scan record (`bomly.scan.v1`)** — the document `scan.Encode` writes and
   `scan.Decode` reads. Additive within v1: new optional keys only, readers
   ignore keys they do not know, `schema_version` names the schema, and
   `Decode` refuses another rather than guessing. A breaking change ships
   as `bomly.scan.v2`.

Plugin binaries built against an older SDK release keep working against newer
hosts (and vice versa) as long as both speak protocol v1.

## Versioning and releases

Releases are plain semver tags (`vX.Y.Z`) cut from `main`. While the module is
v0, minor releases may adjust the in-process Go API (the wire contract stays
additive regardless); patch releases are always safe. Consumers — Bomly itself
and plugin repositories — should pin released versions, never commits or
branches.

Release ordering when the contract changes: this module tags first, plugin
repositories adopt the new tag, then Bomly updates its pin.

## License

Apache-2.0. See [LICENSE](LICENSE).
