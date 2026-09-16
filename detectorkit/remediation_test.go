package detectorkit

import (
	"testing"

	"github.com/bomly-dev/bomly-sdk/testkit"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func TestBuildRemediationHintsResolvesRawDetectionCoordinates(t *testing.T) {
	graph := model.New()
	// Node IDs are canonical package URLs now: a raw detection record without
	// PackageRef resolves through its NodeID.
	dependency := testkit.MustDependencyCoords(t, model.Coordinates{
		Name:      "example",
		Version:   "1.0.0",
		Ecosystem: model.EcosystemNPM,
		Type:      model.PackageTypePackage,
	})
	dependency.Relationship = model.DependencyRelationshipDirect
	dependency.Source = model.DependencySourceRegistry
	if dependency.PackageRef != "" {
		t.Fatalf("test requires a raw dependency without PackageRef: %#v", dependency)
	}
	if err := graph.AddNode(dependency); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	registry := model.NewPackageRegistry()
	registry.Add(&model.Package{
		Coordinates: model.Coordinates{
			PURL:    "pkg:npm/example@1.0.0",
			Name:    "example",
			Version: "1.0.0",
		},
		Remediation: &model.PackageRemediation{
			Status:             model.PackageRemediationComplete,
			RecommendedVersion: "1.2.0",
		},
	})

	response := BuildRemediationHints(plugin.RemediationHintRequest{
		Detection: plugin.DetectionResult{
			SubprojectInfo: plugin.Subproject{
				DetectedPackageManagers: []model.PackageManager{model.PackageManagerNPM},
			},
			Graphs: model.SingleGraphContainer(graph, model.ManifestMetadata{Path: "package-lock.json"}),
		},
		Registry: registry,
	}, model.PackageManagerNPM, []model.RemediationAction{
		model.RemediationActionDirectBump,
		model.RemediationActionTransitiveOverride,
	}, nil)
	if len(response.Hints) != 1 || response.Hints[0].DependencyRef != dependency.NodeID() {
		t.Fatalf("BuildRemediationHints() = %#v", response)
	}
	if !containsHintAction(response.Hints[0].Strategies, model.RemediationActionDirectBump) {
		t.Fatalf("direct strategy missing: %#v", response.Hints[0])
	}
}

func TestBuildRemediationHintsUsesDetectorAdvice(t *testing.T) {
	graph := model.New()
	dependency := testkit.MustDependencyCoords(t, model.Coordinates{
		PURL: "pkg:golang/example.com/lib@1.0.0", Name: "example.com/lib",
		Version: "1.0.0", PackageManager: model.PackageManagerGoMod,
	})
	dependency.PackageRef = "pkg:golang/example.com/lib@1.0.0"
	dependency.Source = model.DependencySourceRegistry
	if err := graph.AddNode(dependency); err != nil {
		t.Fatal(err)
	}
	registry := model.NewPackageRegistry()
	registry.Add(&model.Package{
		Coordinates: dependency.Coordinates,
		Remediation: &model.PackageRemediation{
			Status:             model.PackageRemediationComplete,
			RecommendedVersion: "1.2.0",
		},
	})
	response := BuildRemediationHints(plugin.RemediationHintRequest{
		Detection: plugin.DetectionResult{
			SubprojectInfo: plugin.Subproject{
				DetectedPackageManagers: []model.PackageManager{model.PackageManagerGoMod},
			},
			Graphs: model.SingleGraphContainer(graph, model.ManifestMetadata{Path: "go.mod"}),
		},
		Registry: registry,
	}, model.PackageManagerGoMod, []model.RemediationAction{
		model.RemediationActionDirectBump,
		model.RemediationActionLockfileRefresh,
	}, func(action model.RemediationAction, _, _, _ string) string {
		if action == model.RemediationActionLockfileRefresh {
			return "detector-owned advice"
		}
		return ""
	})
	if len(response.Hints) != 1 {
		t.Fatalf("BuildRemediationHints() = %#v", response)
	}
	for _, strategy := range response.Hints[0].Strategies {
		if strategy.Action == model.RemediationActionLockfileRefresh {
			if strategy.Advice != "detector-owned advice" {
				t.Fatalf("lockfile refresh advice = %q", strategy.Advice)
			}
			return
		}
	}
	t.Fatalf("lockfile refresh strategy missing: %#v", response.Hints[0])
}

func containsHintAction(strategies []plugin.RemediationStrategyHint, target model.RemediationAction) bool {
	for _, strategy := range strategies {
		if strategy.Action == target {
			return true
		}
	}
	return false
}
