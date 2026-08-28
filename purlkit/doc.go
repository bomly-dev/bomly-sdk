// Package purlkit is the single home for package-URL behavior in the Bomly
// SDK (ADR-0038 in bomly-cli's dev-docs/adr). It owns parsing, building, and
// canonicalizing PURLs — including qualifiers and subpath, which the legacy
// root helpers cannot represent — the one purl-type mapping table, and the
// per-ecosystem split of an ecosystem-native name back into org and name.
//
// purlkit is a leaf package: it imports the packageurl library and the
// standard library only, never the root SDK package, so the root package can
// delegate to it without an import cycle. Its APIs are therefore string-typed;
// the typed wrappers live in the root package.
//
// PURL strings are untrusted input (they arrive from lockfiles, SBOM
// documents, and registry APIs). Every entry point validates and returns
// errors or zero values; nothing here panics on malformed input.
package purlkit
