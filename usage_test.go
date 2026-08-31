package sdk

import (
	"encoding/json"
	"testing"
)

// workspaceNode is the case per-site attribution exists for: one package
// version used two ways. In "apps/web" it is a direct development dependency;
// in "apps/api" it is a transitive runtime dependency.
func workspaceNode(t *testing.T) *DependencyNode {
	t.Helper()
	node, err := NewDependencyNode(Coordinates{Name: "left-pad", Version: "1.3.0", Ecosystem: EcosystemNPM})
	if err != nil {
		t.Fatalf("NewDependencyNode: %v", err)
	}
	node.Locations = []PackageLocation{
		{
			RealPath:     "apps/web/package.json",
			ModuleRoot:   "apps/web",
			Scopes:       []Scope{ScopeDevelopment},
			Relationship: DependencyRelationshipDirect,
		},
		{
			RealPath:     "apps/api/package-lock.json",
			ModuleRoot:   "apps/api",
			Scopes:       []Scope{ScopeRuntime},
			Relationship: DependencyRelationshipTransitive,
		},
	}
	return node
}

// TestTheUnionAnswersAQuestionNoUsageAnswers is the defect this whole change
// exists to prevent, stated as a test. Asked of the node's unions, "runtime
// and direct" is true; asked of its usages, it is true of neither. A filter
// that reads the unions reports a package as a direct runtime dependency of a
// workspace where no module uses it that way.
func TestTheUnionAnswersAQuestionNoUsageAnswers(t *testing.T) {
	node := workspaceNode(t)
	node.SyncScopesFromLocations()

	// The union says both scopes, and some location is direct...
	scopes := node.AttributedScopes()
	if len(scopes) != 2 {
		t.Fatalf("AttributedScopes = %v, want both scopes", scopes)
	}
	if !containsScope(scopes, ScopeRuntime) {
		t.Fatal("the union does not carry runtime; the fixture no longer shows the problem")
	}
	directSomewhere := false
	for _, location := range node.Locations {
		if location.Relationship == DependencyRelationshipDirect {
			directSomewhere = true
		}
	}
	if !directSomewhere {
		t.Fatal("no location is direct; the fixture no longer shows the problem")
	}

	// ... but no single usage is both.
	usages := SelectUsages(node, nil, UsageFilter{
		Scope:        ScopeRuntime,
		Relationship: DependencyRelationshipDirect,
	})
	if len(usages) != 0 {
		t.Errorf("runtime AND direct matched %d usages, want none: %+v", len(usages), usages)
	}
}

// TestSelectUsagesMatchesEachSiteOnItsOwnTerms pins that the conjunction is
// evaluated per usage, so each module root gets the answer that is true of it.
func TestSelectUsagesMatchesEachSiteOnItsOwnTerms(t *testing.T) {
	node := workspaceNode(t)

	devDirect := SelectUsages(node, nil, UsageFilter{
		Scope:        ScopeDevelopment,
		Relationship: DependencyRelationshipDirect,
	})
	if len(devDirect) != 1 || devDirect[0].ModuleRoot != "apps/web" {
		t.Errorf("development AND direct = %+v, want only apps/web", devDirect)
	}

	runtimeTransitive := SelectUsages(node, nil, UsageFilter{
		Scope:        ScopeRuntime,
		Relationship: DependencyRelationshipTransitive,
	})
	if len(runtimeTransitive) != 1 || runtimeTransitive[0].ModuleRoot != "apps/api" {
		t.Errorf("runtime AND transitive = %+v, want only apps/api", runtimeTransitive)
	}

	// The zero filter asks nothing and matches every site.
	if all := SelectUsages(node, nil, UsageFilter{}); len(all) != 2 {
		t.Errorf("the zero filter matched %d usages, want 2", len(all))
	}
}

// TestReachabilityJoinsWithinAModuleRoot pins the third term of the
// conjunction: evidence is joined to the site by module root, so a finding
// about one module does not make another module's usage reachable.
func TestReachabilityJoinsWithinAModuleRoot(t *testing.T) {
	node := workspaceNode(t)
	evidence := []ReachabilityEvidence{
		{ModuleRoot: "apps/api", Status: ReachabilityReachable, Tier: TierSymbol},
		{ModuleRoot: "apps/web", Status: ReachabilityUnreachable, Tier: TierPackage},
	}

	// Reachable AND runtime is true of apps/api only.
	got := SelectUsages(node, evidence, UsageFilter{Reachable: true, Scope: ScopeRuntime})
	if len(got) != 1 || got[0].ModuleRoot != "apps/api" {
		t.Fatalf("reachable AND runtime = %+v, want only apps/api", got)
	}
	if got[0].Evidence == nil || got[0].Evidence.Tier != TierSymbol {
		t.Errorf("the usage did not carry its own module's evidence: %+v", got[0].Evidence)
	}

	// Reachable AND development would need apps/web, which is unreachable.
	if got := SelectUsages(node, evidence, UsageFilter{Reachable: true, Scope: ScopeDevelopment}); len(got) != 0 {
		t.Errorf("reachable AND development matched %+v, want none", got)
	}
}

// TestUnattributedEvidenceAppliesEverywhere pins the compatibility path: an
// analyzer that made one whole-scan claim, which is every analyzer before this
// field, still reaches every site.
func TestUnattributedEvidenceAppliesEverywhere(t *testing.T) {
	node := workspaceNode(t)
	global := []ReachabilityEvidence{{Status: ReachabilityReachable, Tier: TierPackage}}

	if got := SelectUsages(node, global, UsageFilter{Reachable: true}); len(got) != 2 {
		t.Errorf("a whole-scan claim reached %d usages, want both", len(got))
	}
	// A module-scoped finding wins over the whole-scan one for its own module.
	mixed := []ReachabilityEvidence{
		{Status: ReachabilityReachable, Tier: TierPackage},
		{ModuleRoot: "apps/web", Status: ReachabilityUnreachable},
	}
	got := SelectUsages(node, mixed, UsageFilter{Reachable: true})
	if len(got) != 1 || got[0].ModuleRoot != "apps/api" {
		t.Errorf("got %+v, want the module-scoped finding to override for apps/web", got)
	}
}

// TestDeriveReachabilityIsAsymmetric pins the rule that matters for safety:
// one reachable finding makes the summary reachable, and unreachable needs
// every piece of evidence to agree. Anything less is unknown, not safe.
func TestDeriveReachabilityIsAsymmetric(t *testing.T) {
	cases := []struct {
		name     string
		evidence []ReachabilityEvidence
		want     ReachabilityStatus
	}{
		{"no evidence", nil, ReachabilityUnknown},
		{"one reachable", []ReachabilityEvidence{{Status: ReachabilityReachable}}, ReachabilityReachable},
		{"one unreachable", []ReachabilityEvidence{{Status: ReachabilityUnreachable}}, ReachabilityUnreachable},
		{
			"reachable anywhere wins",
			[]ReachabilityEvidence{
				{ModuleRoot: "a", Status: ReachabilityUnreachable},
				{ModuleRoot: "b", Status: ReachabilityReachable},
				{ModuleRoot: "c", Status: ReachabilityUnreachable},
			},
			ReachabilityReachable,
		},
		{
			"all unreachable",
			[]ReachabilityEvidence{
				{ModuleRoot: "a", Status: ReachabilityUnreachable},
				{ModuleRoot: "b", Status: ReachabilityUnreachable},
			},
			ReachabilityUnreachable,
		},
		{
			// One module could not be analyzed. That is not evidence of
			// absence, so the summary must not claim unreachable.
			"unreachable beside unknown is unknown",
			[]ReachabilityEvidence{
				{ModuleRoot: "a", Status: ReachabilityUnreachable},
				{ModuleRoot: "b", Status: ReachabilityUnknown},
			},
			ReachabilityUnknown,
		},
		{
			"only unknown",
			[]ReachabilityEvidence{{Status: ReachabilityUnknown}},
			ReachabilityUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DeriveReachability(tc.evidence).Status; got != tc.want {
				t.Errorf("DeriveReachability = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDeriveReachabilityKeepsTheStrongestDetail pins that the summary carries
// the evidence a reader needs to act on, not whichever came first.
func TestDeriveReachabilityKeepsTheStrongestDetail(t *testing.T) {
	hops := 2
	summary := DeriveReachability([]ReachabilityEvidence{
		{ModuleRoot: "a", Status: ReachabilityReachable, Tier: TierPackage, Analyzer: "coarse"},
		{ModuleRoot: "b", Status: ReachabilityReachable, Tier: TierSymbol, Analyzer: "precise", Hops: &hops,
			Symbols: []AffectedSymbol{{Symbol: "Vuln"}}},
	})
	if summary.Tier != TierSymbol || summary.Analyzer != "precise" {
		t.Errorf("summary took the weaker evidence: tier=%q analyzer=%q", summary.Tier, summary.Analyzer)
	}
	if len(summary.Symbols) != 1 || summary.Hops == nil || *summary.Hops != 2 {
		t.Errorf("summary dropped the detail: %+v", summary)
	}
	// The summary is a copy: mutating it must not reach back into the
	// evidence a caller still holds.
	summary.Symbols[0].Symbol = "changed"
	again := DeriveReachability([]ReachabilityEvidence{
		{Status: ReachabilityReachable, Tier: TierSymbol, Symbols: []AffectedSymbol{{Symbol: "Vuln"}}},
	})
	if again.Symbols[0].Symbol != "Vuln" {
		t.Error("the summary aliases its evidence")
	}
}

// TestAttributedScopesFallsBackToTheNode pins the compatibility path for the
// producer side: before detectors record per-site scopes, the node-level set
// is the only record there is and must not be emptied.
func TestAttributedScopesFallsBackToTheNode(t *testing.T) {
	node, err := NewDependencyNode(Coordinates{Name: "left-pad", Version: "1.3.0", Ecosystem: EcosystemNPM})
	if err != nil {
		t.Fatalf("NewDependencyNode: %v", err)
	}
	node.Scopes = []Scope{ScopeRuntime}
	node.Locations = []PackageLocation{{RealPath: "package.json"}} // no attribution

	if got := node.LocationScopes(); got != nil {
		t.Errorf("LocationScopes = %v, want nil when no site carries scopes", got)
	}
	if got := node.AttributedScopes(); len(got) != 1 || got[0] != ScopeRuntime {
		t.Errorf("AttributedScopes = %v, want the node-level set", got)
	}
	node.SyncScopesFromLocations()
	if len(node.Scopes) != 1 || node.Scopes[0] != ScopeRuntime {
		t.Errorf("syncing from empty locations emptied the node: %v", node.Scopes)
	}
}

// TestLocationScopesAreSortedAndDeduplicated pins that the derived union is
// stable, since a document is built from it.
func TestLocationScopesAreSortedAndDeduplicated(t *testing.T) {
	node, err := NewDependencyNode(Coordinates{Name: "left-pad", Version: "1.3.0", Ecosystem: EcosystemNPM})
	if err != nil {
		t.Fatalf("NewDependencyNode: %v", err)
	}
	node.Locations = []PackageLocation{
		{ModuleRoot: "b", Scopes: []Scope{ScopeRuntime, ScopeUnknown}},
		{ModuleRoot: "a", Scopes: []Scope{ScopeDevelopment, ScopeRuntime}},
	}
	got := node.LocationScopes()
	if len(got) != 2 || got[0] != ScopeDevelopment || got[1] != ScopeRuntime {
		t.Errorf("LocationScopes = %v, want [development runtime]", got)
	}
}

// TestUsageFieldsAreOmitEmpty pins that the additive fields vanish from a
// payload that does not set them, so a peer written before them sees the exact
// bytes it saw before.
func TestUsageFieldsAreOmitEmpty(t *testing.T) {
	for name, value := range map[string]any{
		"PackageLocation":      PackageLocation{RealPath: "package.json"},
		"ReachabilityEvidence": ReachabilityEvidence{Status: ReachabilityUnknown},
		"Reachability":         Reachability{Status: ReachabilityUnknown},
	} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var decoded map[string]json.RawMessage
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, field := range []string{"module_root", "scopes", "relationship", "dependency_refs", "evidence"} {
			if _, present := decoded[field]; present {
				t.Errorf("%s wrote %q when it was unset", name, field)
			}
		}
	}
}
