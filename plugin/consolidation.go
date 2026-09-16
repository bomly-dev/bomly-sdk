package plugin

import (
	"github.com/bomly-dev/bomly-sdk/model"
)

// ConsolidatedSubproject describes one subproject included in a consolidated graph.
type ConsolidatedSubproject struct {
	Subproject      Subproject
	DetectorName    string
	RootManifestIDs []string
}

// ConsolidatedManifest describes one selected manifest after detector-level
// deduplication and precedence rules have been applied.
type ConsolidatedManifest struct {
	Entry          model.GraphEntry
	Subproject     Subproject
	DetectorName   string
	Origin         DetectorOrigin
	Technique      DetectorTechnique
	RootManifestID string
}

// ConsolidatedGraph describes a merged view above per-subproject graph results.
type ConsolidatedGraph struct {
	ExecutionTarget ExecutionTarget
	Graphs          *model.GraphContainer
	Manifests       []ConsolidatedManifest
	Subprojects     []ConsolidatedSubproject
}
