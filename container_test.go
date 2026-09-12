package sdk

import (
	"slices"
	"testing"
)

// TestMergeGraphUnionsLocationsAcrossEntries pins the multi-module regression:
// when two entry graphs hold distinct instances of the same node and only one
// carries manifest locations (a gradle `api` dependency appears in both the
// declaring subproject's graph and each consumer's, located only in the
// declaring copy), the merged graph must keep the union of locations
// regardless of merge order.
func TestMergeGraphUnionsLocationsAcrossEntries(t *testing.T) {
	located := PackageLocation{
		RealPath:   "lib/build.gradle",
		AccessPath: "lib/build.gradle",
		Position:   &SourcePosition{File: "lib/build.gradle", Line: 7},
	}
	// maven PURLs require the group-ID namespace, so the fixture carries one.
	const mergedID = "pkg:maven/org.apache.commons/commons-text@1.9"
	newEntry := func(withLocation bool) *Graph {
		g := New()
		dep := mustDep(t, Coordinates{Org: "org.apache.commons", Name: "commons-text", Version: "1.9", Ecosystem: EcosystemMaven})
		if withLocation {
			dep.Locations = []PackageLocation{located}
		}
		if err := g.AddNode(dep); err != nil {
			t.Fatalf("AddNode: %v", err)
		}
		return g
	}

	for name, order := range map[string][]*Graph{
		"bare copy first":  {newEntry(false), newEntry(true)},
		"located first":    {newEntry(true), newEntry(false)},
		"duplicate copies": {newEntry(true), newEntry(true)},
	} {
		merged := New()
		for _, g := range order {
			if err := MergeGraph(merged, g); err != nil {
				t.Fatalf("%s: MergeGraph: %v", name, err)
			}
		}
		node, ok := merged.DependencyNode(mergedID)
		if !ok || node == nil {
			t.Fatalf("%s: merged node missing", name)
		}
		if len(node.Locations) != 1 {
			t.Fatalf("%s: locations = %+v, want exactly one", name, node.Locations)
		}
		loc := node.Locations[0]
		if loc.RealPath != located.RealPath || loc.Position == nil || *loc.Position != *located.Position {
			t.Fatalf("%s: location = %+v, want %+v", name, loc, located)
		}
	}
}

// TestConsolidatedGraphKeepsDeclaringModuleLocation drives the same union
// through the container-level view used by the scan/diff pipelines.
func TestConsolidatedGraphKeepsDeclaringModuleLocation(t *testing.T) {
	consumer := New()
	if err := consumer.AddNode(mustDep(t, Coordinates{Org: "org.apache.commons", Name: "commons-text", Version: "1.9", Ecosystem: EcosystemMaven})); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	declaring := New()
	locatedDep := mustDep(t, Coordinates{Org: "org.apache.commons", Name: "commons-text", Version: "1.9", Ecosystem: EcosystemMaven})
	locatedDep.Locations = []PackageLocation{{
		RealPath: "lib/build.gradle",
		Position: &SourcePosition{File: "lib/build.gradle", Line: 7},
	}}
	if err := declaring.AddNode(locatedDep); err != nil {
		t.Fatalf("AddNode: %v", err)
	}

	container := &GraphContainer{Entries: []GraphEntry{
		{Graph: consumer, Manifest: ManifestMetadata{Path: "app/build.gradle"}},
		{Graph: declaring, Manifest: ManifestMetadata{Path: "lib/build.gradle"}},
	}}
	merged, err := container.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph: %v", err)
	}
	node, ok := merged.DependencyNode("pkg:maven/org.apache.commons/commons-text@1.9")
	if !ok || node == nil {
		t.Fatal("merged node missing")
	}
	if len(node.Locations) != 1 || node.Locations[0].RealPath != "lib/build.gradle" {
		t.Fatalf("locations = %+v, want the declaring module location", node.Locations)
	}
}

// TestMergeGraphKeepsOneUsageRecordPerModuleRoot pins ADR-0037's usage unit
// through the fold: two module roots sharing one declaration path are two
// usages, and the second root's record — with its own scopes and
// relationship — survives whichever entry merges first.
func TestMergeGraphKeepsOneUsageRecordPerModuleRoot(t *testing.T) {
	const mergedID = "pkg:npm/left-pad@1.3.0"
	position := SourcePosition{File: "pnpm-lock.yaml", Line: 42}
	newEntry := func(root string, scopes []Scope, relationship DependencyRelationship) *Graph {
		g := New()
		dep := mustDepPURL(t, mergedID)
		dep.Locations = []PackageLocation{{
			RealPath:     "pnpm-lock.yaml",
			AccessPath:   "pnpm-lock.yaml",
			Position:     &SourcePosition{File: position.File, Line: position.Line},
			ModuleRoot:   root,
			Scopes:       scopes,
			Relationship: relationship,
		}}
		if err := g.AddNode(dep); err != nil {
			t.Fatalf("AddNode: %v", err)
		}
		return g
	}
	entryA := func() *Graph {
		return newEntry("packages/a", []Scope{ScopeRuntime}, DependencyRelationshipDirect)
	}
	entryB := func() *Graph {
		return newEntry("packages/b", []Scope{ScopeDevelopment}, DependencyRelationshipTransitive)
	}

	for name, order := range map[string][]*Graph{
		"a then b": {entryA(), entryB()},
		"b then a": {entryB(), entryA()},
	} {
		merged := New()
		for _, g := range order {
			if err := MergeGraph(merged, g); err != nil {
				t.Fatalf("%s: MergeGraph: %v", name, err)
			}
		}
		node, ok := merged.DependencyNode(mergedID)
		if !ok || node == nil {
			t.Fatalf("%s: merged node missing", name)
		}
		if len(node.Locations) != 2 {
			t.Fatalf("%s: locations = %+v, want one record per module root", name, node.Locations)
		}
		byRoot := make(map[string]PackageLocation, 2)
		for _, loc := range node.Locations {
			if loc.RealPath != position.File || loc.Position == nil || *loc.Position != position {
				t.Fatalf("%s: record %+v does not name the shared site", name, loc)
			}
			byRoot[loc.ModuleRoot] = loc
		}
		a, ok := byRoot["packages/a"]
		if !ok || !slices.Equal(a.Scopes, []Scope{ScopeRuntime}) || a.Relationship != DependencyRelationshipDirect {
			t.Errorf("%s: packages/a record = %+v, want runtime/direct", name, a)
		}
		b, ok := byRoot["packages/b"]
		if !ok || !slices.Equal(b.Scopes, []Scope{ScopeDevelopment}) || b.Relationship != DependencyRelationshipTransitive {
			t.Errorf("%s: packages/b record = %+v, want development/transitive", name, b)
		}
	}
}

// TestMergeGraphFoldsIdenticalAttributedRecords pins the other half of the
// usage rule: two witnesses of one fully attributed usage are one record,
// and folding does not duplicate its scopes.
func TestMergeGraphFoldsIdenticalAttributedRecords(t *testing.T) {
	const mergedID = "pkg:npm/left-pad@1.3.0"
	newEntry := func() *Graph {
		g := New()
		dep := mustDepPURL(t, mergedID)
		dep.Locations = []PackageLocation{{
			RealPath:     "packages/a/package.json",
			AccessPath:   "packages/a/package.json",
			Position:     &SourcePosition{File: "packages/a/package.json", Line: 12},
			ModuleRoot:   "packages/a",
			Scopes:       []Scope{ScopeRuntime},
			Relationship: DependencyRelationshipDirect,
		}}
		if err := g.AddNode(dep); err != nil {
			t.Fatalf("AddNode: %v", err)
		}
		return g
	}
	merged := New()
	for _, g := range []*Graph{newEntry(), newEntry()} {
		if err := MergeGraph(merged, g); err != nil {
			t.Fatalf("MergeGraph: %v", err)
		}
	}
	node, ok := merged.DependencyNode(mergedID)
	if !ok || node == nil {
		t.Fatal("merged node missing")
	}
	if len(node.Locations) != 1 {
		t.Fatalf("locations = %+v, want the identical records folded into one", node.Locations)
	}
	loc := node.Locations[0]
	if !slices.Equal(loc.Scopes, []Scope{ScopeRuntime}) || loc.Relationship != DependencyRelationshipDirect {
		t.Errorf("folded record = %+v, want runtime/direct without duplicated scopes", loc)
	}
}

// TestMergeGraphUnionsAttributionOnAMatchedUsageRecord pins what a matched
// usage record does with a second witness's attribution: scopes union and
// the relationship resolves rank-max, in either merge order, and the
// node-level scope set stays a superset of its sites.
func TestMergeGraphUnionsAttributionOnAMatchedUsageRecord(t *testing.T) {
	const mergedID = "pkg:npm/left-pad@1.3.0"
	newEntry := func(scopes []Scope, relationship DependencyRelationship) *Graph {
		g := New()
		dep := mustDepPURL(t, mergedID)
		dep.Locations = []PackageLocation{{
			RealPath:     "packages/a/package.json",
			AccessPath:   "packages/a/package.json",
			Position:     &SourcePosition{File: "packages/a/package.json", Line: 12},
			ModuleRoot:   "packages/a",
			Scopes:       scopes,
			Relationship: relationship,
		}}
		if err := g.AddNode(dep); err != nil {
			t.Fatalf("AddNode: %v", err)
		}
		return g
	}
	development := func() *Graph {
		return newEntry([]Scope{ScopeDevelopment}, DependencyRelationshipTransitive)
	}
	runtime := func() *Graph {
		return newEntry([]Scope{ScopeRuntime}, DependencyRelationshipDirect)
	}

	for name, order := range map[string][]*Graph{
		"development then runtime": {development(), runtime()},
		"runtime then development": {runtime(), development()},
	} {
		merged := New()
		for _, g := range order {
			if err := MergeGraph(merged, g); err != nil {
				t.Fatalf("%s: MergeGraph: %v", name, err)
			}
		}
		node, ok := merged.DependencyNode(mergedID)
		if !ok || node == nil {
			t.Fatalf("%s: merged node missing", name)
		}
		if len(node.Locations) != 1 {
			t.Fatalf("%s: locations = %+v, want one record for one usage", name, node.Locations)
		}
		loc := node.Locations[0]
		if !slices.Equal(loc.Scopes, []Scope{ScopeDevelopment, ScopeRuntime}) {
			t.Errorf("%s: record scopes = %v, want the union of both witnesses", name, loc.Scopes)
		}
		if loc.Relationship != DependencyRelationshipDirect {
			t.Errorf("%s: record relationship = %q, want direct (rank-max)", name, loc.Relationship)
		}
		if !node.HasScope(ScopeDevelopment) || !node.HasScope(ScopeRuntime) {
			t.Errorf("%s: node scopes = %v, want a superset of the site's", name, node.Scopes)
		}
	}
}
