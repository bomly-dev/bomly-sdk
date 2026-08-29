// Package identitykit is the single home for the byte-level grammar of
// dependency identity (ADR-0036 in bomly-cli's dev-docs/adr): the readable
// node ID — a canonical package URL or an escaped coordinate fallback base,
// plus an optional occurrence suffix — and the versioned content address
// over the identity facets. SPEC.md in this directory is the normative
// grammar, and the golden vectors in testdata/identity_vectors.json pin
// every byte, so independent implementations must agree.
//
// Every identifier here is derived, never authored: the readable ID and the
// content address are pure functions of the identity facets, so validation
// is re-derivation, and a value that contradicts its facets is repaired by
// re-deriving rather than trusted.
//
// identitykit is a leaf package: it imports the standard library only —
// never the root SDK package and never purlkit. The grammar treats the
// package-identity base as an opaque escaped string (a canonical package
// URL percent-encodes spaces by construction, and the coordinate fallback
// escapes them here), so joining and splitting an ID needs no package-URL
// knowledge. Identity strings are untrusted input; every parsing entry
// point bounds its input and returns zero values or errors on malformed
// data — nothing here panics.
package identitykit
