// Package spdxkit is the single home for SPDX license behavior in the Bomly
// SDK (ADR-0038 in bomly-cli's dev-docs/adr): expression validation,
// classification, deprecated-identifier canonicalization, and deterministic
// LicenseRef minting.
//
// License strings are untrusted input everywhere — they arrive from
// lockfiles a repository commits and from registry APIs — and the underlying
// SPDX expression parser panics on some of them ("(((" dereferences a nil
// operator). Every entry point here contains that and reports the value as
// one it could not parse, which is what an unparseable license is. No other
// package may import github.com/github/go-spdx directly; the module's
// import-boundary test fails when a call site bypasses this package.
//
// spdxkit is a leaf package: it imports go-spdx and the standard library
// only, never the root SDK package, so both the root package and the helper
// kits can build on it without an import cycle.
package spdxkit
