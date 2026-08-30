package sdk

import "testing"

func TestDependencyRegistryMatchEligible(t *testing.T) {
	// Eligibility is a DependencyNode method now: ownership and structure are
	// the node kind, so the old first-party and manifest rows cannot exist —
	// module and manifest nodes never reach this method. Only the source
	// classification (plus the Swift source-control special case) decides.
	newDep := func(source DependencySource) *DependencyNode {
		node := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "example", Version: "1.0.0"})
		node.Source = source
		return node
	}
	newSwiftDep := func(source DependencySource) *DependencyNode {
		node := mustDepPURL(t, "pkg:swift/github.com/acme/example@1.0.0")
		node.Source = source
		return node
	}
	mirror := newDep(DependencySourceRegistry)
	mirror.ResolvedURL = "https://mirror.example.test/pkg.tgz"
	imported := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "bundled-app", Version: "2.0.0", Type: PackageTypeApplication})
	imported.Source = DependencySourceRegistry

	for _, tc := range []struct {
		name string
		dep  *DependencyNode
		want bool
	}{
		{name: "registry release", dep: newDep(DependencySourceRegistry), want: true},
		{name: "registry mirror", dep: mirror, want: true},
		{name: "legacy unspecified", dep: newDep(""), want: true},
		{name: "plugin custom unspecified semantics", dep: newDep(DependencySource("custom")), want: true},
		{name: "project", dep: newDep(DependencySourceProject)},
		{name: "workspace", dep: newDep(DependencySourceWorkspace)},
		{name: "file", dep: newDep(DependencySourceFile)},
		{name: "git", dep: newDep(DependencySourceGit)},
		{name: "Swift source control", dep: newSwiftDep(DependencySourceGit), want: true},
		{name: "Swift local path", dep: newSwiftDep(DependencySourceFile)},
		{name: "url", dep: newDep(DependencySourceURL)},
		// An application type imported from an SBOM is an artifact kind, not
		// an ownership signal: it is a dependency node and stays eligible.
		{name: "imported application", dep: imported, want: true},
		{name: "nil"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.dep.RegistryMatchEligible(); got != tc.want {
				t.Fatalf("RegistryMatchEligible() = %v, want %v", got, tc.want)
			}
		})
	}
}
