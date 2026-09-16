// Package sdk is the module root of Bomly's public Go contract. It declares
// nothing itself; the contract is split across four packages by what each
// answers, and this file is the map.
//
//   - model: what the data is. The dependency graph and its node kinds,
//     packages and the registry, vulnerabilities and findings, the controlled
//     vocabularies, and the normalization, merge, and policy rules they
//     share. Every type here is also a wire payload.
//   - plugin: what a component is. The Detector, Matcher, Auditor, and
//     Analyzer interfaces, their descriptors and request/response types, the
//     Base* defaults, and Module/HostContext, which let one component run
//     embedded in the host or as a managed plugin without change.
//   - runtime: how a component runs out of process. ServeModule and the
//     Serve* entrypoints for a plugin binary's main, and Client,
//     HandshakeConfig, and ClientPluginMap for the host that launches it,
//     over the HashiCorp go-plugin gRPC transport.
//   - httpkit: outbound HTTP with Bomly's proxy and CA policy, reached by a
//     component through HostContext.HTTPClient.
//
// Which package to import: implementing a component means plugin and model;
// a plugin binary's main means runtime; hosting plugins means runtime; the
// helper kits (detectorkit, matcherkit, testkit, conformance, purlkit,
// spdxkit, sbom, system, filecache, logkit) build on the same four.
//
// The plugin wire protocol, bomly.plugin.v1, is JSON over gRPC and strictly
// additive: its payload types are the model and plugin structs, so their
// JSON tags are the wire schema, and fields are never removed, renamed, or
// repurposed within v1.
package sdk
