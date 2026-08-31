package sdk

import (
	"fmt"
	"strings"

	spdxcommon "github.com/spdx/tools-golang/spdx/v2/common"
)

// EdgeKind says what an edge between two nodes asserts.
//
// Every edge used to mean the same thing, because every node was a dependency
// and the only relationship was "depends on". With the typed node union a
// graph also holds manifests and modules, and the edge from a manifest to the
// module it declares is not a dependency claim -- exporting it as one puts a
// relationship in a document that no detector asserted.
type EdgeKind string

const (
	// EdgeKindUnknown is an edge whose kind was never stated. It is what a
	// payload written before this field carried, and it is derived from the
	// nodes it joins rather than published as-is.
	EdgeKindUnknown EdgeKind = ""
	// EdgeKindDependsOn is the dependency claim: the source needs the target.
	EdgeKindDependsOn EdgeKind = "depends-on"
	// EdgeKindDescribes joins a manifest to a module it declares. It is a
	// structural edge, not a dependency: a package.json does not depend on the
	// workspace member it describes.
	EdgeKindDescribes EdgeKind = "describes"
)

// spdxRelationshipNames maps each kind to its SPDX relationship spelling.
//
// The spellings are spdx/tools-golang's own constants, so a rename upstream is
// a compile error here rather than a document Bomly emits that SPDX rejects.
// The mapping itself is Bomly's: no library states what a manifest-to-module
// edge means, because no library has that node kind.
//
// The reverse direction -- reading SPDX's forty-odd relationship types back
// into edges -- is not here. Bomly produces these two and consumes neither;
// an ingesting codec that needs the full vocabulary is the SBOM codec's
// concern, and mapping types nothing produces would be vocabulary with no
// caller to keep it honest.
var spdxRelationshipNames = map[EdgeKind]string{
	EdgeKindDependsOn: spdxcommon.TypeRelationshipDependsOn,
	EdgeKindDescribes: spdxcommon.TypeRelationshipDescribe,
}

// ParseEdgeKind normalizes an edge kind read from a payload. An empty value is
// unknown, which is legal and is what every pre-field payload carries; anything
// else unrecognized is an error, so a kind Bomly cannot read fails a decode
// rather than silently becoming a dependency claim.
func ParseEdgeKind(value string) (EdgeKind, error) {
	if len(value) > maxVocabularyTokenLength {
		return EdgeKindUnknown, fmt.Errorf(
			"edge kind is %d bytes, over the %d byte limit", len(value), maxVocabularyTokenLength)
	}
	switch kind := EdgeKind(strings.ToLower(strings.TrimSpace(value))); kind {
	case EdgeKindUnknown, EdgeKindDependsOn, EdgeKindDescribes:
		return kind, nil
	default:
		return EdgeKindUnknown, fmt.Errorf("unsupported edge kind %q", value)
	}
}

// SPDXName returns the kind's SPDX relationship spelling, or "" when it has
// none. A caller emitting SPDX treats "" as "this edge has no projection" and
// writes no relationship, rather than guessing one.
func (k EdgeKind) SPDXName() string { return spdxRelationshipNames[k] }

// String returns the canonical token.
func (k EdgeKind) String() string { return string(k) }

// DeriveEdgeKind names what an edge between two nodes asserts, from the kinds
// of the nodes themselves.
//
// This is what makes the field safe to add: a graph built before the field
// existed, or by a caller that does not set it, still exports correct
// relationships, because the structure already carries the answer. Only a
// manifest-to-module edge is structural; everything else is a dependency
// claim, including a manifest that names a dependency directly, which is what
// a lockfile with no workspace layer produces.
func DeriveEdgeKind(from, to GraphNode) EdgeKind {
	if from == nil || to == nil {
		return EdgeKindUnknown
	}
	if from.Kind() == NodeKindManifest && to.Kind() == NodeKindModule {
		return EdgeKindDescribes
	}
	return EdgeKindDependsOn
}

// MergeEdgeKind combines two kinds for one edge, which happens when graphs
// merge or duplicate nodes fold.
//
// A stated kind beats an unstated one, so folding a legacy edge into a typed
// one keeps the type. Two different stated kinds disagree about what the edge
// means; the dependency claim wins, because it is the stronger assertion and
// losing it would drop the edge from a dependency-only export.
func MergeEdgeKind(current, next EdgeKind) EdgeKind {
	switch {
	case next == EdgeKindUnknown:
		return current
	case current == EdgeKindUnknown:
		return next
	case current == next:
		return current
	default:
		return EdgeKindDependsOn
	}
}
