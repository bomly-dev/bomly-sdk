package detectorkit

import (
	"testing"

	sdk "github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/testkit"
)

func TestBuildRemediationHintsResolvesRawDetectionCoordinates(t *testing.T) {
	graph := sdk.New()
	// Node IDs are canonical package URLs now: a raw detection record without
	// PackageRef resolves through its NodeID.
	dependency := testkit.MustDependencyCoords(t, sdk.Coordinates{
		Name:      "example",
		Version:   "1.0.0",
		Ecosystem: sdk.EcosystemNPM,
		Type:      sdk.PackageTypePackage,
	})
	dependency.Relationship = sdk.DependencyRelationshipDirect
	dependency.Source = sdk.DependencySourceRegistry
	if dependency.PackageRef != "" {
		t.Fatalf("test requires a raw dependency without PackageRef: %#v", dependency)
	}
	if err := graph.AddNode(dependency); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	registry := sdk.NewPackageRegistry()
	registry.Add(&sdk.Package{
		Coordinates: sdk.Coordinates{
			PURL:    "pkg:npm/example@1.0.0",
			Name:    "example",
			Version: "1.0.0",
		},
		Remediation: &sdk.PackageRemediation{
			Status:             sdk.PackageRemediationComplete,
			RecommendedVersion: "1.2.0",
		},
	})

	response := BuildRemediationHints(sdk.RemediationHintRequest{
		Detection: sdk.DetectionResult{
			SubprojectInfo: sdk.Subproject{
				DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			},
			Graphs: sdk.SingleGraphContainer(graph, sdk.ManifestMetadata{Path: "package-lock.json"}),
		},
		Registry: registry,
	}, sdk.PackageManagerNPM, []sdk.RemediationAction{
		sdk.RemediationActionDirectBump,
		sdk.RemediationActionTransitiveOverride,
	}, nil)
	if len(response.Hints) != 1 || response.Hints[0].DependencyRef != dependency.NodeID() {
		t.Fatalf("BuildRemediationHints() = %#v", response)
	}
	if !containsHintAction(response.Hints[0].Strategies, sdk.RemediationActionDirectBump) {
		t.Fatalf("direct strategy missing: %#v", response.Hints[0])
	}
}

func TestBuildRemediationHintsUsesDetectorAdvice(t *testing.T) {
	graph := sdk.New()
	dependency := testkit.MustDependencyCoords(t, sdk.Coordinates{
		PURL: "pkg:golang/example.com/lib@1.0.0", Name: "example.com/lib",
		Version: "1.0.0", PackageManager: sdk.PackageManagerGoMod,
	})
	dependency.PackageRef = "pkg:golang/example.com/lib@1.0.0"
	dependency.Source = sdk.DependencySourceRegistry
	if err := graph.AddNode(dependency); err != nil {
		t.Fatal(err)
	}
	registry := sdk.NewPackageRegistry()
	registry.Add(&sdk.Package{
		Coordinates: dependency.Coordinates,
		Remediation: &sdk.PackageRemediation{
			Status:             sdk.PackageRemediationComplete,
			RecommendedVersion: "1.2.0",
		},
	})
	response := BuildRemediationHints(sdk.RemediationHintRequest{
		Detection: sdk.DetectionResult{
			SubprojectInfo: sdk.Subproject{
				DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerGoMod},
			},
			Graphs: sdk.SingleGraphContainer(graph, sdk.ManifestMetadata{Path: "go.mod"}),
		},
		Registry: registry,
	}, sdk.PackageManagerGoMod, []sdk.RemediationAction{
		sdk.RemediationActionDirectBump,
		sdk.RemediationActionLockfileRefresh,
	}, func(action sdk.RemediationAction, _, _, _ string) string {
		if action == sdk.RemediationActionLockfileRefresh {
			return "detector-owned advice"
		}
		return ""
	})
	if len(response.Hints) != 1 {
		t.Fatalf("BuildRemediationHints() = %#v", response)
	}
	for _, strategy := range response.Hints[0].Strategies {
		if strategy.Action == sdk.RemediationActionLockfileRefresh {
			if strategy.Advice != "detector-owned advice" {
				t.Fatalf("lockfile refresh advice = %q", strategy.Advice)
			}
			return
		}
	}
	t.Fatalf("lockfile refresh strategy missing: %#v", response.Hints[0])
}

func containsHintAction(strategies []sdk.RemediationStrategyHint, target sdk.RemediationAction) bool {
	for _, strategy := range strategies {
		if strategy.Action == target {
			return true
		}
	}
	return false
}
