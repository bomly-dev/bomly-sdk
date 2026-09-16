# Bomly SDK

<p align="center">
  <a href="https://github.com/bomly-dev/bomly-sdk/actions/workflows/ci.yml"><img src="https://github.com/bomly-dev/bomly-sdk/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/bomly-dev/bomly-sdk"><img src="https://api.scorecard.dev/projects/github.com/bomly-dev/bomly-sdk/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://github.com/bomly-dev/bomly-sdk/releases/latest"><img src="https://img.shields.io/github/v/release/bomly-dev/bomly-sdk?sort=semver" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/bomly-dev/bomly-sdk" alt="License: Apache-2.0"></a>
  <a href="https://pkg.go.dev/github.com/bomly-dev/bomly-sdk"><img src="https://pkg.go.dev/badge/github.com/bomly-dev/bomly-sdk.svg" alt="Go Reference"></a>
</p>

`github.com/bomly-dev/bomly-sdk` is the contract module for building Bomly
components: detectors, matchers, auditors, and analyzers. It contains the
neutral domain types (dependencies, packages, vulnerabilities, findings, the
package registry) and the component interfaces; the `plugin` subpackage is the
managed-plugin runtime (serving adapters and gRPC protocol) used by external
plugin binaries and by the host that launches them.

```sh
go get github.com/bomly-dev/bomly-sdk@latest
```

## Building a plugin

A Bomly plugin is a standalone Go binary that imports this module and serves
one component over the managed-plugin runtime:

```go
package main

import (
	sdk "github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func main() {
	plugin.ServeModule(sdk.Module{
		Kind:     sdk.PluginKindDetector,
		Detector: &sdk.DetectorModule{Descriptor: descriptor, Support: support, New: newDetector},
	})
}
```

See the [Bomly plugin documentation](https://github.com/bomly-dev/bomly-cli/blob/main/docs/PLUGINS.md)
for the full authoring guide, packaging layout (`bomly-plugin.json`), and
installation flow.

Embed the `Base*` types (`sdk.BaseDetector`, `sdk.BaseMatcher`,
`sdk.BaseAuditor`, `sdk.BaseAnalyzer`) in your implementation so future
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
- `plugin` — the managed-plugin runtime: `ServeModule` and the `Serve*` entrypoints for plugin binaries, `Client`, `HandshakeConfig`, and `ClientPluginMap` for the host, and the per-process plugin environment (`DecodePluginConfigFromEnv`).
- `httpkit` — proxy- and CA-aware outbound HTTP clients from explicit configuration or the `BOMLY_HTTP_*` environment; `HostContext.HTTPClient()` returns its `ClientProvider`.
- `purlkit` — the single home for package-URL behavior: parsing, building, canonicalizing, the purl-type mapping table, and the per-ecosystem name split, over packageurl-go and go-pep440-version.
- `spdxkit` — the single home for SPDX license behavior: expression validation, classification, deprecated-identifier canonicalization, and deterministic `LicenseRef` minting, containing go-spdx's panics on untrusted input.
- `conformance` — the reusable plugin-contract test suite: run it against your `sdk.Module` for descriptor validity, JSON round-trip stability, host-context construction, the Ready/Applicable lifecycle, role capabilities, and optionally a transport probe of the built binary.

The root package is one flat package. Files are named for the concept they
own and every test file pairs with the source file of the same stem;
`AGENTS.md` carries the map.

## Migrating to v0.13

v0.13.0 moved the managed-plugin runtime and the HTTP client provider out of
the root package. The wire protocol is unchanged; only import paths and a few
spellings move:

| Before (`sdk.`) | After |
|---|---|
| `ServeModule`, `ServeDetector`, `ServeMatcher`, `ServeAuditor`, `ServeAnalyzer` | `plugin.` (same names) |
| `Client`, `HandshakeConfig`, `ClientPluginMap`, `EnvVerbosity` | `plugin.` (same names) |
| `EnvPluginConfigFile`, `EnvPluginID`, `RawPluginConfigFromEnv`, `DecodePluginConfigFromEnv` | `plugin.` (same names) |
| `HTTPClientProvider`, `HTTPClientConfig` | `httpkit.ClientProvider`, `httpkit.ClientConfig` |
| `NewHTTPClientProvider`, `NewHTTPClientProviderFromEnv` | `httpkit.NewClientProvider`, `httpkit.NewClientProviderFromEnv` |
| `HTTPClientConfigFromEnv`, `NewHTTPClient` | `httpkit.ClientConfigFromEnv`, `httpkit.NewClient` |
| `EnvHTTP*` constants | `httpkit.EnvHTTP*` (same names) |

`HostContext.HTTPClient()` now returns `*httpkit.ClientProvider`, so every
implementer of the interface changes that one return type. `ConfigSchemaFor`
and `MustConfigSchemaFor` stay in the root. Import the runtime as
`sdkplugin "github.com/bomly-dev/bomly-sdk/plugin"` in a file whose own
package is called `plugin`.

## The SBOM codec

- `sbom` — the SBOM codec: projects a graph into SPDX 2.3 or CycloneDX JSON and reads such a document back into a graph, with the document model, the strict ingest preflight, and the assertions a document carries about itself.
- `graphview` — what a document may say about a node: the package URL it publishes, which of its children a document can name, and which nodes count as top-level parents.

Both come from the CLI's `internal/sbom` and `internal/graphview`
(bomly-cli ADR-0045). The CLI and the Syft and Grype plugins adopt this
package from the release that carries it, in that order -- the plugins
first, then the CLI, which pins both -- and delete their copies as they do.

## Compatibility

Two independent compatibility axes govern this module:

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
