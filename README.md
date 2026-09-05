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
package registry), the component interfaces, and the managed-plugin serving
adapters and gRPC protocol used by external plugin binaries.

```sh
go get github.com/bomly-dev/bomly-sdk@latest
```

## Building a plugin

A Bomly plugin is a standalone Go binary that imports this module and serves
one component over the managed-plugin runtime:

```go
package main

import sdk "github.com/bomly-dev/bomly-sdk"

func main() {
	sdk.ServeDetector(myDetector{})
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
