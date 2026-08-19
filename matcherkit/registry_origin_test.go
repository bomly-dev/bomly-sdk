package matcherkit_test

import (
	"testing"

	sdk "github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/matcherkit"
)

// node builds one dependency occurrence of a package with a chosen origin.
func node(t *testing.T, id, artifactURL string) *sdk.Dependency {
	t.Helper()
	dep := sdk.NewDependencyWithID(id, sdk.Dependency{
		Coordinates: sdk.Coordinates{
			Name: "lodash", Version: "4.17.21", Ecosystem: sdk.EcosystemNPM, PURL: "pkg:npm/lodash@4.17.21",
		},
	})
	if artifactURL != "" {
		dep.Origin = sdk.ArtifactOrigin(artifactURL)
	}
	return dep
}

// A package is enriched once however many dependencies reference it, but every
// occurrence still gets a say about where it came from -- otherwise the
// registry publishes whichever was walked first.
func TestRegistryPackagesReconcileOriginAcrossOccurrences(t *testing.T) {
	const (
		public  = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
		private = "https://npm.corp/mirror/lodash/-/lodash-4.17.21.tgz"
	)

	cases := []struct {
		name  string
		left  string
		right string
		want  string
	}{
		{name: "occurrences agree", left: public, right: public, want: public},
		{name: "occurrences disagree", left: public, right: private},
		{name: "one occurrence says nothing", left: public, right: "", want: public},
		{name: "a later occurrence fills the gap", left: "", right: public, want: public},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := sdk.New()
			for _, dep := range []*sdk.Dependency{node(t, "web:lodash", tc.left), node(t, "api:lodash", tc.right)} {
				if err := g.AddNode(dep); err != nil {
					t.Fatal(err)
				}
			}

			registry := sdk.NewPackageRegistry()
			packages := matcherkit.RegistryPackagesForGraph(g, registry, nil)
			if len(packages) != 1 {
				t.Fatalf("registry packages = %d, want 1: the package is enriched once", len(packages))
			}

			origin := packages[0].Origin.Normalized()
			if tc.want == "" {
				if origin != nil {
					t.Fatalf("origin = %+v, want none", origin)
				}
				return
			}
			if origin == nil || origin.ArtifactURL != tc.want {
				t.Fatalf("origin = %+v, want %q", origin, tc.want)
			}
		})
	}
}
