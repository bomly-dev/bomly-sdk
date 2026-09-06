package sdk

import (
	"sort"
	"testing"
)

func TestFilterGraphByScope(t *testing.T) {
	depsGraph := New()
	// The project's own root is a module node under the union — a
	// structural record retained by kind, never scope-filtered, which is
	// what keeps an edgeless graph or an orphan structural record from
	// disappearing. A scope-less *dependency* node is a different question,
	// answered by TestAnUnassertedScopeStaysInARuntimeView.
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

// TestAnUnassertedScopeStaysInARuntimeView pins the policy that a filter
// selects on assertions and that absence is not one.
//
// A runtime view keeps a dependency that asserted no scope, because nothing
// about it says it is outside what ships, and dropping it would hide a
// package from vulnerability triage on the strength of a claim nobody made.
// A development view still requires the assertion: a package that might ship
// must not appear in the list a user reads as the one they can deprioritize.
// One rule, applied twice -- an unasserted scope resolves toward "may be in
// production", the only direction that cannot hide a finding.
//
// Before this, an unscoped dependency was invisible to both views. SPDX has
// no scope concept, so every package in a third-party SPDX document arrives
// unscoped and a runtime view of one held nothing but structural nodes.
func TestAnUnassertedScopeStaysInARuntimeView(t *testing.T) {
	graph := New()
	root := mustModule(t, "package.json", Coordinates{Name: "app", Version: "1.0.0"})
	unscoped := mustDep(t, Coordinates{Name: "left-pad", Version: "1.3.0"})
	// A scope only a newer build knows is the same case: this build cannot
	// read it, so it has not been told the dependency is development.
	unreadable := mustDep(t, Coordinates{Name: "right-pad", Version: "1.0.0"})
	unreadable.Scopes = []Scope{"future"}
	dev := mustDep(t, Coordinates{Name: "vitest", Version: "2.0.0"})
	dev.Scopes = ScopesOf(ScopeDevelopment)
	for _, node := range []GraphNode{root, unscoped, unreadable, dev} {
		if err := graph.AddNode(node); err != nil {
			t.Fatalf("add %q: %v", node.NodeID(), err)
		}
	}

	runtimeView, report, err := FilterGraphByScopeWithReport(graph, ScopeRuntime)
	if err != nil {
		t.Fatalf("runtime filter: %v", err)
	}
	for _, node := range []*DependencyNode{unscoped, unreadable} {
		if _, ok := runtimeView.Node(node.NodeID()); !ok {
			t.Errorf("%q was dropped from a runtime view despite asserting no scope", node.NodeID())
		}
	}
	if _, ok := runtimeView.Node(dev.NodeID()); ok {
		t.Error("an affirmatively development dependency survived a runtime view")
	}

	// The filter narrowed nothing for those two, and says so rather than
	// leaving a mostly-unfiltered result looking filtered.
	want := []string{unscoped.NodeID(), unreadable.NodeID()}
	sort.Strings(want)
	if len(report.Unasserted) != len(want) {
		t.Fatalf("report = %v, want the two unasserted nodes %v", report.Unasserted, want)
	}
	for i, id := range want {
		if report.Unasserted[i] != id {
			t.Errorf("report[%d] = %q, want %q (sorted)", i, report.Unasserted[i], id)
		}
	}

	developmentView, devReport, err := FilterGraphByScopeWithReport(graph, ScopeDevelopment)
	if err != nil {
		t.Fatalf("development filter: %v", err)
	}
	for _, node := range []*DependencyNode{unscoped, unreadable} {
		if _, ok := developmentView.Node(node.NodeID()); ok {
			t.Errorf("%q entered a development view without asserting development", node.NodeID())
		}
	}
	if _, ok := developmentView.Node(dev.NodeID()); !ok {
		t.Error("the development dependency was dropped from a development view")
	}
	if len(devReport.Unasserted) != 0 {
		t.Errorf("development report = %v, want empty: nothing is kept on absence there", devReport.Unasserted)
	}
}

// TestScopeSetMatchesIsTheOneRule pins the predicate both filter sites route
// through, so the graph filter and the usage filter cannot drift apart on
// what an absent scope means.
func TestScopeSetMatchesIsTheOneRule(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		scopes  []Scope
		want    Scope
		matches bool
	}{
		{"runtime view keeps runtime", ScopesOf(ScopeRuntime), ScopeRuntime, true},
		{"runtime view keeps a mixed set", ScopesOf(ScopeRuntime, ScopeDevelopment), ScopeRuntime, true},
		{"runtime view keeps an empty set", nil, ScopeRuntime, true},
		{"runtime view keeps an unreadable scope", []Scope{"future"}, ScopeRuntime, true},
		{"runtime view keeps an explicit unknown", []Scope{ScopeUnknown}, ScopeRuntime, true},
		{"runtime view drops development", ScopesOf(ScopeDevelopment), ScopeRuntime, false},
		{"development view needs the assertion", nil, ScopeDevelopment, false},
		{"development view drops an unreadable scope", []Scope{"future"}, ScopeDevelopment, false},
		{"development view keeps development", ScopesOf(ScopeDevelopment), ScopeDevelopment, true},
		{"no filter matches everything", nil, ScopeUnknown, true},
		{"no filter matches development too", ScopesOf(ScopeDevelopment), ScopeUnknown, true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := ScopeSetMatches(testCase.scopes, testCase.want); got != testCase.matches {
				t.Errorf("ScopeSetMatches(%v, %q) = %v, want %v", testCase.scopes, testCase.want, got, testCase.matches)
			}
		})
	}
}

// A nil node matches nothing rather than panicking, since a graph walk can
// hand a typed nil to a filter.
func TestMatchesScopeFilterOnANilNode(t *testing.T) {
	var node *DependencyNode
	if node.MatchesScopeFilter(ScopeRuntime) {
		t.Error("a nil dependency matched a runtime view")
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
