package plugin

import (
	"testing"

	"github.com/bomly-dev/bomly-sdk/model"
)

func TestFilterDetectionResultByScope_FiltersEntryPackages(t *testing.T) {
	depsGraph := model.New()
	root := mustDependency(t, model.Coordinates{Name: "app", Version: "1.0.0"})
	runtimeDep := mustDependency(t, model.Coordinates{Ecosystem: model.EcosystemNPM, Name: "react", Version: "18.2.0"})
	runtimeDep.Scopes = model.ScopesOf(model.ScopeRuntime)
	devDep := mustDependency(t, model.Coordinates{Ecosystem: model.EcosystemNPM, Name: "vitest", Version: "2.0.0"})
	devDep.Scopes = model.ScopesOf(model.ScopeDevelopment)
	for _, pkg := range []*model.DependencyNode{root, runtimeDep, devDep} {
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
		Graphs: &model.GraphContainer{Entries: []model.GraphEntry{{
			Graph:    depsGraph,
			Manifest: model.ManifestMetadata{Path: "package-lock.json"},
			Packages: []*model.Package{
				{Coordinates: model.Coordinates{PURL: model.BuildPackageURL("npm", "", "react", "18.2.0")}},
				{Coordinates: model.Coordinates{PURL: model.BuildPackageURL("npm", "", "vitest", "2.0.0")}},
			},
		}}},
	}

	filtered, err := FilterDetectionResultByScope(result, model.ScopeRuntime)
	if err != nil {
		t.Fatalf("FilterDetectionResultByScope() error = %v", err)
	}
	entry := filtered.Graphs.Entries[0]
	if len(entry.Packages) != 1 || entry.Packages[0].PURL != model.BuildPackageURL("npm", "", "react", "18.2.0") {
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
			graph, runtimeID, devID := representativeScopedGraph(t, model.Ecosystem(tt.ecosystem))
			result := DetectionResult{
				Graphs: &model.GraphContainer{Entries: []model.GraphEntry{{
					Graph:    graph,
					Manifest: model.ManifestMetadata{Path: tt.manifest},
				}}},
			}
			filtered, err := FilterDetectionResultByScope(result, model.ScopeRuntime)
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

func representativeScopedGraph(t *testing.T, ecosystem model.Ecosystem) (*model.Graph, string, string) {
	t.Helper()
	graph := model.New()
	coords := func(name string) model.Coordinates {
		c := model.Coordinates{Ecosystem: ecosystem, Name: name, Version: "1.0.0"}
		if ecosystem == model.EcosystemMaven || ecosystem == "packagist" {
			// maven and composer PURLs require a namespace.
			c.Org = "org.example"
		}
		return c
	}
	root := mustDependency(t, coords(string(ecosystem)+"-app"))
	runtimeDep := mustDependency(t, coords(string(ecosystem)+"-runtime"))
	runtimeDep.Scopes = model.ScopesOf(model.ScopeRuntime)
	devDep := mustDependency(t, coords(string(ecosystem)+"-dev"))
	devDep.Scopes = model.ScopesOf(model.ScopeDevelopment)
	for _, dep := range []*model.DependencyNode{root, runtimeDep, devDep} {
		if err := graph.AddNode(dep); err != nil {
			t.Fatalf("add %q: %v", dep.NodeID(), err)
		}
	}
	if err := graph.AddEdge(root.NodeID(), runtimeDep.NodeID()); err != nil {
		t.Fatalf("add runtime edge: %v", err)
	}
	if err := graph.AddEdge(root.NodeID(), devDep.NodeID()); err != nil {
		t.Fatalf("add development edge: %v", err)
	}
	return graph, runtimeDep.NodeID(), devDep.NodeID()
}
