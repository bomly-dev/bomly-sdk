package matcherkit

import (
	"testing"

	sdk "github.com/bomly-dev/bomly-sdk"
)

func TestRegistryPackagesForGraphSkipsFirstPartyNodes(t *testing.T) {
	graph := sdk.New()
	app := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{
		Ecosystem: sdk.EcosystemMaven, PackageManager: sdk.PackageManagerMaven,
		Org: "com.acme", Name: "my-module", Version: "1.0.0",
		Type: sdk.PackageTypeApplication, FirstParty: true, PURL: "pkg:maven/com.acme/my-module@1.0.0",
	}})
	manifest := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{
		Name: "pom.xml", Type: sdk.PackageTypeManifest,
	}})
	pkg := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{
		Ecosystem: sdk.EcosystemMaven, PackageManager: sdk.PackageManagerMaven,
		Org: "com.guava", Name: "guava", Version: "31.0",
		PURL: "pkg:maven/com.guava/guava@31.0",
	}})
	for _, node := range []*sdk.Dependency{app, manifest, pkg} {
		if err := graph.AddNode(node); err != nil {
			t.Fatalf("add node %q: %v", node.Name, err)
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
	if app.PackageRef != "" {
		t.Fatalf("first-party node must not be linked to an enrichment package, got PackageRef %q", app.PackageRef)
	}
}

// TestRegistryPackagesForGraphKeepsImportedApplicationComponents locks in
// that ownership is the FirstParty marker, never the component type: an
// application-typed component imported from an SBOM document is an artifact
// kind (CycloneDX/SPDX), not proof it belongs to the scanned project, and
// must keep flowing to enrichment.
func TestRegistryPackagesForGraphKeepsImportedApplicationComponents(t *testing.T) {
	graph := sdk.New()
	imported := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{
		Ecosystem: sdk.EcosystemNPM, Name: "bundled-app", Version: "2.0.0",
		Type: sdk.PackageTypeApplication, PURL: "pkg:npm/bundled-app@2.0.0",
	}})
	if err := graph.AddNode(imported); err != nil {
		t.Fatalf("add node: %v", err)
	}

	registry := sdk.NewPackageRegistry()
	packages := RegistryPackagesForGraph(graph, registry, nil)
	if len(packages) != 1 || packages[0].Name != "bundled-app" {
		t.Fatalf("expected the imported application component to stay enrichable, got %#v", packages)
	}
}

func TestRegistryPackagesForGraphTargetRespectsFirstParty(t *testing.T) {
	graph := sdk.New()
	app := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{
		Ecosystem: sdk.EcosystemNPM, PackageManager: sdk.PackageManagerNPM,
		Name: "my-app", Version: "1.0.0",
		Type: sdk.PackageTypeApplication, FirstParty: true, PURL: "pkg:npm/my-app@1.0.0",
	}})
	if err := graph.AddNode(app); err != nil {
		t.Fatalf("add node: %v", err)
	}

	registry := sdk.NewPackageRegistry()
	if packages := RegistryPackagesForGraph(graph, registry, app); len(packages) != 0 {
		t.Fatalf("expected first-party target to yield no enrichable packages, got %#v", packages)
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
