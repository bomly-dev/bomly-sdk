package matcherkit

import (
	"testing"

	sdk "github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/testkit"
)

func TestRegistryPackagesForGraphSkipsFirstPartyNodes(t *testing.T) {
	graph := sdk.New()
	// First-party ownership and manifest structure are node kinds now:
	// module and manifest nodes never reach matching.
	app := testkit.MustModuleNode(t, "pom.xml", sdk.Coordinates{
		Ecosystem: sdk.EcosystemMaven, PackageManager: sdk.PackageManagerMaven,
		Org: "com.acme", Name: "my-module", Version: "1.0.0",
		Type: sdk.PackageTypeApplication,
	})
	manifest, err := sdk.NewManifestNode("pom.xml", sdk.ManifestKindPomXML)
	if err != nil {
		t.Fatalf("NewManifestNode: %v", err)
	}
	pkg := testkit.MustDependencyNode(t, "pkg:maven/com.guava/guava@31.0")
	for _, node := range []sdk.GraphNode{app, manifest, pkg} {
		if err := graph.AddNode(node); err != nil {
			t.Fatalf("add node %q: %v", node.NodeID(), err)
		}
	}

	registry := sdk.NewPackageRegistry()
	packages := RegistryPackagesForGraph(graph, registry, nil)

	if len(packages) != 1 || packages[0].Name != "guava" {
		t.Fatalf("expected only the third-party package to be enrichable, got %#v", packages)
	}
	if _, ok := registry.Get("pkg:maven/com.acme/my-module@1.0.0"); ok {
		t.Fatal("first-party application package must not be seeded for enrichment")
	}
}

// TestRegistryPackagesForGraphKeepsImportedApplicationComponents locks in
// that ownership is the module kind, never the component type: an
// application-typed component imported from an SBOM document is an artifact
// kind (CycloneDX/SPDX), not proof it belongs to the scanned project, and
// must keep flowing to enrichment.
func TestRegistryPackagesForGraphKeepsImportedApplicationComponents(t *testing.T) {
	graph := sdk.New()
	imported := testkit.MustDependencyCoords(t, sdk.Coordinates{
		Ecosystem: sdk.EcosystemNPM, Name: "bundled-app", Version: "2.0.0",
		Type: sdk.PackageTypeApplication,
	})
	if err := graph.AddNode(imported); err != nil {
		t.Fatalf("add node: %v", err)
	}

	registry := sdk.NewPackageRegistry()
	packages := RegistryPackagesForGraph(graph, registry, nil)
	if len(packages) != 1 || packages[0].Name != "bundled-app" {
		t.Fatalf("expected the imported application component to stay enrichable, got %#v", packages)
	}
}

// The target parameter is typed *sdk.DependencyNode now, so a first-party
// module can no longer be passed as a target at all — the old runtime
// first-party guard became a compile-time guarantee. What remains observable
// is that a set target limits enrichment to that dependency alone.
func TestRegistryPackagesForGraphTargetLimitsToTarget(t *testing.T) {
	graph := sdk.New()
	target := testkit.MustDependencyNode(t, "pkg:npm/left-pad@1.3.0")
	other := testkit.MustDependencyNode(t, "pkg:npm/lodash@4.17.21")
	for _, node := range []sdk.GraphNode{target, other} {
		if err := graph.AddNode(node); err != nil {
			t.Fatalf("add node: %v", err)
		}
	}

	registry := sdk.NewPackageRegistry()
	packages := RegistryPackagesForGraph(graph, registry, target)
	if len(packages) != 1 || packages[0].PURL != "pkg:npm/left-pad@1.3.0" {
		t.Fatalf("expected only the target package, got %#v", packages)
	}
	if _, ok := registry.Get("pkg:npm/lodash@4.17.21"); ok {
		t.Fatal("non-target packages must not be seeded when a target is set")
	}
}

func TestMissingLicensePackagesAndNormalizeLicenseSet(t *testing.T) {
	packages := []*sdk.Package{
		nil,
		{Coordinates: sdk.Coordinates{Name: "has-license", Version: "1.0.0"},
			Licenses: []sdk.PackageLicense{{Value: "MIT"}}},
		{Coordinates: sdk.Coordinates{Name: "", Version: "1.0.0"}},
		{Coordinates: sdk.Coordinates{Name: "no-version", Version: " "}},
		{Coordinates: sdk.Coordinates{Name: "eligible", Version: "2.0.0"}},
	}
	eligible := MissingLicensePackages(packages)
	if len(eligible) != 1 || eligible[0].Name != "eligible" {
		t.Fatalf("MissingLicensePackages() = %#v, want only the eligible package", eligible)
	}

	licenses := NormalizeLicenseSet([]string{" MIT ", "MIT", "", "Apache-2.0"}, "declared")
	if len(licenses) != 2 {
		t.Fatalf("NormalizeLicenseSet() = %#v, want deduplicated MIT and Apache-2.0", licenses)
	}
	if licenses[0].Value != "MIT" || licenses[0].SPDXExpression != "MIT" || licenses[0].Type != sdk.LicenseType("declared") {
		t.Fatalf("NormalizeLicenseSet()[0] = %#v", licenses[0])
	}
	if licenses[1].Value != "Apache-2.0" {
		t.Fatalf("NormalizeLicenseSet()[1] = %#v", licenses[1])
	}
}
