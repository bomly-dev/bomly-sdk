package sdk

import "testing"

func TestFilterGraphByScope(t *testing.T) {
	depsGraph := New()
	// The project's own root is a module node under the union — a
	// structural record retained by kind. A scope-less dependency node is
	// not structural and is filtered like any other dependency, which is
	// what keeps an edgeless graph or an orphan record from slipping
	// development dependencies past a runtime filter.
	root := mustModule(t, "package.json", Coordinates{Name: "app", Version: "1.0.0"})
	runtimeDep := mustDep(t, Coordinates{Name: "react", Version: "18.2.0"})
	runtimeDep.Scopes = ScopesOf(ScopeRuntime)
	devDep := mustDep(t, Coordinates{Name: "vitest", Version: "2.0.0"})
	devDep.Scopes = ScopesOf(ScopeDevelopment)
	sharedDep := mustDep(t, Coordinates{Name: "shared", Version: "1.0.0"})
	sharedDep.Scopes = ScopesOf(ScopeDevelopment, ScopeRuntime)
	if err := depsGraph.AddNode(root); err != nil {
		t.Fatalf("add module root: %v", err)
	}
	for _, pkg := range []*DependencyNode{runtimeDep, devDep, sharedDep} {
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
	if err := depsGraph.AddEdge(root.NodeID(), sharedDep.NodeID()); err != nil {
		t.Fatalf("add shared dependency: %v", err)
	}

	filtered, err := FilterGraphByScope(depsGraph, ScopeRuntime)
	if err != nil {
		t.Fatalf("FilterGraphByScope() error = %v", err)
	}
	if filtered.Size() != 3 {
		t.Fatalf("expected 3 packages after runtime filter, got %d", filtered.Size())
	}
	if _, ok := filtered.Node(runtimeDep.NodeID()); !ok {
		t.Fatal("expected runtime dependency to be kept")
	}
	if _, ok := filtered.Node(sharedDep.NodeID()); !ok {
		t.Fatal("expected dependency shared with runtime to be kept")
	}
	if _, ok := filtered.Node(devDep.NodeID()); ok {
		t.Fatal("expected development dependency to be removed")
	}

	filtered, err = FilterGraphByScope(depsGraph, ScopeDevelopment)
	if err != nil {
		t.Fatalf("FilterGraphByScope() error = %v", err)
	}
	if _, ok := filtered.Node(devDep.NodeID()); !ok {
		t.Fatal("expected development dependency to be kept")
	}
	if _, ok := filtered.Node(runtimeDep.NodeID()); ok {
		t.Fatal("expected runtime dependency to be removed")
	}
	if _, ok := filtered.Node(sharedDep.NodeID()); ok {
		t.Fatal("expected runtime-primary shared dependency to be removed from development filter")
	}
}

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

func representativeScopedGraph(t *testing.T, ecosystem Ecosystem) (*Graph, string, string) {
	t.Helper()
	graph := New()
	coords := func(name string) Coordinates {
		c := Coordinates{Ecosystem: ecosystem, Name: name, Version: "1.0.0"}
		if ecosystem == EcosystemMaven || ecosystem == "packagist" {
			// maven and composer PURLs require a namespace.
			c.Org = "org.example"
		}
		return c
	}
	root := mustDep(t, coords(string(ecosystem)+"-app"))
	runtimeDep := mustDep(t, coords(string(ecosystem)+"-runtime"))
	runtimeDep.Scopes = ScopesOf(ScopeRuntime)
	devDep := mustDep(t, coords(string(ecosystem)+"-dev"))
	devDep.Scopes = ScopesOf(ScopeDevelopment)
	for _, dep := range []*DependencyNode{root, runtimeDep, devDep} {
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
