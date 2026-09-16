package sdk

import (
	"testing"
)

func TestFilterDetectionResultByScope_FiltersEntryPackages(t *testing.T) {
	depsGraph := New()
	root := mustDep(t, Coordinates{Name: "app", Version: "1.0.0"})
	runtimeDep := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "react", Version: "18.2.0"})
	runtimeDep.Scopes = ScopesOf(ScopeRuntime)
	devDep := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "vitest", Version: "2.0.0"})
	devDep.Scopes = ScopesOf(ScopeDevelopment)
	for _, pkg := range []*DependencyNode{root, runtimeDep, devDep} {
		if err := depsGraph.AddNode(pkg); err != nil {
			t.Fatalf("add package %q: %v", pkg.NodeID(), err)
		}
	}
	if err := depsGraph.AddEdge(root.NodeID(), runtimeDep.NodeID()); err != nil {
		t.Fatalf("add runtime dependency: %v", err)
	}
	if err := depsGraph.AddEdge(root.NodeID(), devDep.NodeID()); err != nil {
		t.Fatalf("add development dependency: %v", err)
	}

	result := DetectionResult{
		Graphs: &GraphContainer{Entries: []GraphEntry{{
			Graph:    depsGraph,
			Manifest: ManifestMetadata{Path: "package-lock.json"},
			Packages: []*Package{
				{Coordinates: Coordinates{PURL: BuildPackageURL("npm", "", "react", "18.2.0")}},
				{Coordinates: Coordinates{PURL: BuildPackageURL("npm", "", "vitest", "2.0.0")}},
			},
		}}},
	}

	filtered, err := FilterDetectionResultByScope(result, ScopeRuntime)
	if err != nil {
		t.Fatalf("FilterDetectionResultByScope() error = %v", err)
	}
	entry := filtered.Graphs.Entries[0]
	if len(entry.Packages) != 1 || entry.Packages[0].PURL != BuildPackageURL("npm", "", "react", "18.2.0") {
		t.Fatalf("expected only runtime package facts, got %#v", entry.Packages)
	}
}

func TestFilterDetectionResultByScope_RepresentativeParserOutputs(t *testing.T) {
	cases := []struct {
		name      string
		ecosystem string
		manifest  string
	}{
		{"npm lockfile", "npm", "package-lock.json"},
		{"pnpm lockfile", "npm", "pnpm-lock.yaml"},
		{"yarn lockfile", "npm", "yarn.lock"},
		{"composer lockfile", "packagist", "composer.lock"},
		{"bundler lockfile", "rubygems", "Gemfile.lock"},
		{"nuget lockfile", "nuget", "packages.lock.json"},
		{"pub lockfile", "pub", "pubspec.lock"},
		{"mix lockfile", "hex", "mix.lock"},
		{"conan manifest", "conan", "conanfile.txt"},
		{"cocoapods lockfile", "cocoapods", "Podfile.lock"},
		{"sbt lockfile", "maven", "build.sbt"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			graph, runtimeID, devID := representativeScopedGraph(t, Ecosystem(tt.ecosystem))
			result := DetectionResult{
				Graphs: &GraphContainer{Entries: []GraphEntry{{
					Graph:    graph,
					Manifest: ManifestMetadata{Path: tt.manifest},
				}}},
			}
			filtered, err := FilterDetectionResultByScope(result, ScopeRuntime)
			if err != nil {
				t.Fatalf("FilterDetectionResultByScope() error = %v", err)
			}
			filteredGraph := filtered.Graphs.Entries[0].Graph
			if _, ok := filteredGraph.Node(runtimeID); !ok {
				t.Fatalf("expected runtime dependency for %s: %s", tt.name, filteredGraph.PrettyString())
			}
			if _, ok := filteredGraph.Node(devID); ok {
				t.Fatalf("expected development dependency to be filtered for %s: %s", tt.name, filteredGraph.PrettyString())
			}
		})
	}
}
