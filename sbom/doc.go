// Package sbom is the SBOM codec: it projects a dependency graph into an
// SPDX 2.3 or CycloneDX document and reads such a document back into a graph.
//
// It owns the document model (Document, Component, Dependency and the
// assertions they carry), the two format codecs, the strict preflight that
// refuses a document without one unambiguous reading (bomly-cli ADR-0039),
// and the projection in both directions: FromDepGraph and FromGraphEntries
// build a Document from a graph, ToGraph builds a graph from a Document, and
// MarshalJSON / UnmarshalJSON move a Document to and from bytes.
//
// This package is the one home for that behaviour (bomly-cli ADR-0045). It
// was the CLI's internal/sbom, copied into two plugin repositories and drifted
// there; the plugins and then the CLI adopt this package from the release
// that carries it and delete their copies. What a document may name of a
// graph -- the questions every renderer and exporter asks of a node -- is the
// sibling package graphview.
package sbom
