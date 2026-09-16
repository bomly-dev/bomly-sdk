package model

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

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

// TestSelectUsagesAppliesTheAbsenceRule pins that the usage filter answers an
// unasserted scope the same way the graph filter does, because both route
// through ScopeSetMatches. A site that carries no scopes is what a producer
// which has not migrated to per-site attribution leaves behind, so this is
// the common shape rather than an unusual one, and a runtime question about
// it must not answer "no usage" when nothing said the site is outside what
// ships.
func TestSelectUsagesAppliesTheAbsenceRule(t *testing.T) {
	node := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "left-pad", Version: "1.3.0"})
	node.Locations = []PackageLocation{
		{RealPath: "package.json", ModuleRoot: "apps/web"},
		{RealPath: "apps/api/package.json", ModuleRoot: "apps/api", Scopes: ScopesOf(ScopeDevelopment)},
	}

	// A runtime question keeps the unscoped site and drops the one that said
	// development.
	runtimeUsages := SelectUsages(node, nil, UsageFilter{Scope: ScopeRuntime})
	if len(runtimeUsages) != 1 || runtimeUsages[0].ModuleRoot != "apps/web" {
		t.Errorf("runtime usages = %+v, want only the unscoped apps/web site", runtimeUsages)
	}

	// A development question still requires the assertion, so the unscoped
	// site does not appear in the view a user reads as safe to deprioritize.
	developmentUsages := SelectUsages(node, nil, UsageFilter{Scope: ScopeDevelopment})
	if len(developmentUsages) != 1 || developmentUsages[0].ModuleRoot != "apps/api" {
		t.Errorf("development usages = %+v, want only the site that asserted development", developmentUsages)
	}
}

// TestUnknownSummariesKeepTheirReason pins that a summary over undecided
// evidence still explains itself. "unknown" with no reason tells a reader
// nothing, while "missing-toolchain" is actionable -- and the reason is the
// entire content of an unknown result.
//
// Found migrating the govulncheck analyzer: its degraded-runner path sets a
// reason on each module's evidence, and the derived summary dropped it.
func TestUnknownSummariesKeepTheirReason(t *testing.T) {
	summary := DeriveReachability([]ReachabilityEvidence{
		{ModuleRoot: "a", Status: ReachabilityUnknown, Tier: TierNone, Reason: "missing-toolchain", Analyzer: "govulncheck"},
	})
	if summary.Status != ReachabilityUnknown {
		t.Fatalf("status = %q, want unknown", summary.Status)
	}
	if summary.Reason != "missing-toolchain" {
		t.Errorf("reason = %q, want it carried into the summary", summary.Reason)
	}
	if summary.Analyzer != "govulncheck" || summary.Tier != TierNone {
		t.Errorf("summary dropped detail: %+v", summary)
	}
	// A mixed set is still unknown, and still explains itself.
	mixed := DeriveReachability([]ReachabilityEvidence{
		{ModuleRoot: "a", Status: ReachabilityUnreachable, Reason: "package-not-imported"},
		{ModuleRoot: "b", Status: ReachabilityUnknown, Reason: "missing-toolchain"},
	})
	// It must be the *unknown* item's reason, not the first item's. Taking
	// evidence[0] here reported "package-not-imported" as the reason the
	// aggregate was unknown, which is both wrong and order-dependent.
	if mixed.Status != ReachabilityUnknown || mixed.Reason != "missing-toolchain" {
		t.Errorf("mixed summary = %+v, want unknown explained by the unknown item", mixed)
	}
	// ... whichever order the two arrive in.
	flipped := DeriveReachability([]ReachabilityEvidence{
		{ModuleRoot: "b", Status: ReachabilityUnknown, Reason: "missing-toolchain"},
		{ModuleRoot: "a", Status: ReachabilityUnreachable, Reason: "package-not-imported"},
	})
	if flipped.Reason != mixed.Reason {
		t.Errorf("the reason depends on evidence order: %q vs %q", mixed.Reason, flipped.Reason)
	}
	// No evidence at all has nothing to explain.
	if got := DeriveReachability(nil); got.Status != ReachabilityUnknown || got.Reason != "" {
		t.Errorf("empty evidence gave %+v", got)
	}
}

// TestUnknownSummaryPrefersAnExplainedItem pins the second half of the reason
// rule. Selecting simply the first unknown item was still order-dependent:
// two roots both unknown, the first silent and the second carrying
// "missing-toolchain", gave a bare unknown that changed when the evidence was
// reordered. The explanation is the whole content of an unknown result, so an
// item that has one wins.
func TestUnknownSummaryPrefersAnExplainedItem(t *testing.T) {
	silentFirst := DeriveReachability([]ReachabilityEvidence{
		{ModuleRoot: "a", Status: ReachabilityUnknown},
		{ModuleRoot: "b", Status: ReachabilityUnknown, Reason: "missing-toolchain"},
	})
	explainedFirst := DeriveReachability([]ReachabilityEvidence{
		{ModuleRoot: "b", Status: ReachabilityUnknown, Reason: "missing-toolchain"},
		{ModuleRoot: "a", Status: ReachabilityUnknown},
	})
	if silentFirst.Reason != "missing-toolchain" {
		t.Errorf("reason = %q, want the explained item to win", silentFirst.Reason)
	}
	if silentFirst.Reason != explainedFirst.Reason {
		t.Errorf("the reason depends on evidence order: %q vs %q", silentFirst.Reason, explainedFirst.Reason)
	}
	// A whitespace-only reason explains nothing and does not win either.
	blank := DeriveReachability([]ReachabilityEvidence{
		{ModuleRoot: "a", Status: ReachabilityUnknown, Reason: "   "},
		{ModuleRoot: "b", Status: ReachabilityUnknown, Reason: "missing-toolchain"},
	})
	if blank.Reason != "missing-toolchain" {
		t.Errorf("reason = %q, want a blank reason to lose to a real one", blank.Reason)
	}
	// With nothing explained anywhere, it is still unknown and still stable.
	none := DeriveReachability([]ReachabilityEvidence{
		{ModuleRoot: "a", Status: ReachabilityUnknown},
		{ModuleRoot: "b", Status: ReachabilityUnknown},
	})
	if none.Status != ReachabilityUnknown || none.Reason != "" {
		t.Errorf("got %+v, want a bare unknown when nothing explains itself", none)
	}
	// Whitespace is not an explanation on the way out either. Trimming only
	// while choosing left the raw value to be published, so a set whose only
	// reasons were blank returned "   " -- and returned "" when reversed.
	for _, order := range [][]ReachabilityEvidence{
		{{ModuleRoot: "a", Status: ReachabilityUnknown, Reason: "   "}, {ModuleRoot: "b", Status: ReachabilityUnknown}},
		{{ModuleRoot: "b", Status: ReachabilityUnknown}, {ModuleRoot: "a", Status: ReachabilityUnknown, Reason: "   "}},
	} {
		if got := DeriveReachability(order); got.Reason != "" {
			t.Errorf("a whitespace-only reason published as %q", got.Reason)
		}
	}
}

// TestUndecidedIsWiderThanUnknown pins that a status which is neither
// reachable nor unreachable counts as undecided when a diagnostic is chosen,
// not only the exact "unknown" spelling.
//
// ReachabilityEvidence has no decode gate, so an item can arrive with its
// status omitted or misspelled. The count that decides "unreachable" already
// treats such an item as undecided -- one of them is enough to stop the
// aggregate being unreachable -- so the reason selection has to agree, or an
// item with a real reason loses to a decided item's misleading one.
func TestUndecidedIsWiderThanUnknown(t *testing.T) {
	for _, status := range []ReachabilityStatus{"", "not-a-status", ReachabilityUnknown} {
		summary := DeriveReachability([]ReachabilityEvidence{
			{ModuleRoot: "a", Status: ReachabilityUnreachable, Reason: "package-not-imported"},
			{ModuleRoot: "b", Status: status, Reason: "missing-toolchain"},
		})
		if summary.Status != ReachabilityUnknown {
			t.Errorf("status %q: aggregate = %q, want unknown", status, summary.Status)
		}
		if summary.Reason != "missing-toolchain" {
			t.Errorf("status %q: reason = %q, want the undecided item's explanation", status, summary.Reason)
		}
	}
}

// sitedNode builds one dependency node with the sites given, so a test can
// state exactly what the producer recorded and nothing else.
func sitedNode(t *testing.T, name string, locations ...PackageLocation) *DependencyNode {
	t.Helper()
	node, err := NewDependencyNode(Coordinates{Name: name, Version: "1.0.0", Ecosystem: EcosystemNPM})
	if err != nil {
		t.Fatalf("NewDependencyNode(%s): %v", name, err)
	}
	node.Locations = locations
	return node
}

// graphOf wires nodes into a graph, which is what NewRootAttributor
// calibrates against.
func graphOf(t *testing.T, nodes ...*DependencyNode) *Graph {
	t.Helper()
	g := New()
	for _, node := range nodes {
		if err := g.AddNode(node); err != nil {
			t.Fatalf("AddNode(%s): %v", node.NodeID(), err)
		}
	}
	return g
}

// TestDeclaredRootAttributesTheSiteAndExcludesTheOthers is the rule at its
// simplest: a site that names this root establishes the occurrence, and --
// once the two vocabularies are known to overlap -- a site that names only
// another root says the node is not here at all.
func TestDeclaredRootAttributesTheSiteAndExcludesTheOthers(t *testing.T) {
	node := sitedNode(t, "left-pad", PackageLocation{ModuleRoot: "/ws/api"})
	attributor := NewRootAttributor([]string{"/ws/api", "/ws/web"}, graphOf(t, node))

	if got := attributor.Attribute(node, "/ws/api"); got != AttributedToSite {
		t.Errorf("Attribute(own root) = %v, want %v", got, AttributedToSite)
	}
	if got := attributor.Attribute(node, "/ws/web"); got != AttributedElsewhere {
		t.Errorf("Attribute(other root) = %v, want %v", got, AttributedElsewhere)
	}
}

// TestDeclaredRootsAreOnlyTrustedWhenTheyShareOurVocabulary guards the
// degradation path, which is the half most likely to be lost in a rewrite.
// Detectors record the root they resolved from and an analyzer derives roots
// from the filesystem; when the two spellings do not overlap, a non-match
// means they are speaking past each other, not that the package is absent --
// and dropping the node would lose the finding outright.
func TestDeclaredRootsAreOnlyTrustedWhenTheyShareOurVocabulary(t *testing.T) {
	node := sitedNode(t, "left-pad", PackageLocation{ModuleRoot: "apps/api", RealPath: "apps/api/package.json"})
	attributor := NewRootAttributor([]string{"/ws/api", "/ws/web"}, graphOf(t, node))

	if got := attributor.Attribute(node, "/ws/api"); got != AttributedToRootOnly {
		t.Errorf("Attribute under a foreign vocabulary = %v, want %v: the evidence must survive with the root as its floor", got, AttributedToRootOnly)
	}
}

// TestOneOverlappingSiteCalibratesTheWholePass pins that calibration is a
// property of the run, not of the node in hand: the node that shares the
// vocabulary licenses reading the other node's mismatch as absence.
func TestOneOverlappingSiteCalibratesTheWholePass(t *testing.T) {
	overlapping := sitedNode(t, "left-pad", PackageLocation{ModuleRoot: "/ws/web"})
	foreign := sitedNode(t, "right-pad", PackageLocation{ModuleRoot: "/elsewhere/lib"})
	attributor := NewRootAttributor([]string{"/ws/api", "/ws/web"}, graphOf(t, overlapping, foreign))

	if got := attributor.Attribute(foreign, "/ws/api"); got != AttributedElsewhere {
		t.Errorf("Attribute(node declaring only a foreign root) = %v, want %v once the run's roots are known to be the same vocabulary", got, AttributedElsewhere)
	}
}

// TestSitePathAttributesWithoutADeclaredRoot covers the path half of the
// rule. A vendored or nested copy lives inside the module that installed it,
// so its path alone says which root it belongs to.
func TestSitePathAttributesWithoutADeclaredRoot(t *testing.T) {
	apiRoot := filepath.Join("/ws", "api")
	webRoot := filepath.Join("/ws", "web")
	node := sitedNode(t, "left-pad", PackageLocation{
		RealPath: filepath.Join(apiRoot, "node_modules", "left-pad", "index.js"),
	})
	attributor := NewRootAttributor([]string{apiRoot, webRoot}, graphOf(t, node))

	if got := attributor.Attribute(node, apiRoot); got != AttributedToSite {
		t.Errorf("Attribute(root containing the site) = %v, want %v", got, AttributedToSite)
	}
	if got := attributor.Attribute(node, webRoot); got != AttributedElsewhere {
		t.Errorf("Attribute(sibling root) = %v, want %v: the copy is installed in a tree this run knows about, and it is not this one", got, AttributedElsewhere)
	}
}

// TestSiteOutsideEveryAnalyzedRootIsNotAbsence separates "installed
// somewhere else we analyze" from "installed somewhere we know nothing
// about". A module cache or a global store says nothing either way, and
// reading it as absence would drop every Go and Python finding.
func TestSiteOutsideEveryAnalyzedRootIsNotAbsence(t *testing.T) {
	node := sitedNode(t, "left-pad", PackageLocation{
		RealPath: filepath.Join("/home", "user", "go", "pkg", "mod", "left-pad@v1.0.0", "lib.go"),
	})
	attributor := NewRootAttributor([]string{"/ws/api", "/ws/web"}, graphOf(t, node))

	if got := attributor.Attribute(node, "/ws/api"); got != AttributedToRootOnly {
		t.Errorf("Attribute(site in a shared store) = %v, want %v", got, AttributedToRootOnly)
	}
}

// TestSiblingRootPrefixIsNotContainment pins that containment is a question
// about path elements, not about string prefixes: "/ws/apifoo" is not inside
// "/ws/api", and treating it as inside would attribute one module's install
// tree to its neighbour.
func TestSiblingRootPrefixIsNotContainment(t *testing.T) {
	node := sitedNode(t, "left-pad", PackageLocation{
		RealPath: filepath.Join("/ws", "apifoo", "node_modules", "left-pad", "index.js"),
	})
	attributor := NewRootAttributor([]string{"/ws/api"}, graphOf(t, node))

	if got := attributor.Attribute(node, "/ws/api"); got != AttributedToRootOnly {
		t.Errorf("Attribute(sibling whose name shares a prefix) = %v, want %v", got, AttributedToRootOnly)
	}
}

// TestDirectoryNamedLikeAnEscapeIsStillInsideTheRoot pins the containment
// test against the near miss the copies carried: a leading ".." must be a
// whole path element. Kubernetes secret mounts really do name a directory
// "..data", and reading that as an escape puts a site outside the root that
// contains it.
func TestDirectoryNamedLikeAnEscapeIsStillInsideTheRoot(t *testing.T) {
	root := filepath.Join("/ws", "api")
	node := sitedNode(t, "left-pad", PackageLocation{
		RealPath: filepath.Join(root, "..data", "node_modules", "left-pad", "index.js"),
	})
	attributor := NewRootAttributor([]string{root}, graphOf(t, node))

	if got := attributor.Attribute(node, root); got != AttributedToSite {
		t.Errorf("Attribute(site under a %q directory) = %v, want %v", "..data", got, AttributedToSite)
	}
}

// TestUncomparablePathsDoNotAttribute covers the mismatch filepath.Rel
// reports: a relative site path against an absolute root is neither inside
// nor outside it, and must read as neither.
func TestUncomparablePathsDoNotAttribute(t *testing.T) {
	node := sitedNode(t, "left-pad", PackageLocation{RealPath: filepath.Join("apps", "api", "package.json")})
	attributor := NewRootAttributor([]string{"/ws/api"}, graphOf(t, node))

	if got := attributor.Attribute(node, "/ws/api"); got != AttributedToRootOnly {
		t.Errorf("Attribute(relative site, absolute root) = %v, want %v", got, AttributedToRootOnly)
	}
}

// TestAttributeEdgeCasesKeepEvidence pins the answers that must never drop a
// finding: an unattributed node, an empty root (the whole-scan claim), and a
// zero-value attributor.
func TestAttributeEdgeCasesKeepEvidence(t *testing.T) {
	sited := sitedNode(t, "left-pad", PackageLocation{ModuleRoot: "/ws/api", RealPath: "/ws/api/package.json"})
	bare := sitedNode(t, "right-pad")
	attributor := NewRootAttributor([]string{"/ws/api"}, graphOf(t, sited, bare))

	if got := attributor.Attribute(bare, "/ws/api"); got != AttributedToRootOnly {
		t.Errorf("Attribute(node with no sites) = %v, want %v", got, AttributedToRootOnly)
	}
	if got := attributor.Attribute(sited, ""); got != AttributedToRootOnly {
		t.Errorf("Attribute(empty root) = %v, want %v: a whole-scan claim covers every site", got, AttributedToRootOnly)
	}
	if got := attributor.Attribute(sited, "   "); got != AttributedToRootOnly {
		t.Errorf("Attribute(blank root) = %v, want %v", got, AttributedToRootOnly)
	}

	var zero RootAttributor
	if got := zero.Attribute(sited, "/ws/api"); got != AttributedToSite {
		t.Errorf("zero attributor on the node's own root = %v, want %v", got, AttributedToSite)
	}
	if got := zero.Attribute(sited, "/ws/web"); got != AttributedToRootOnly {
		t.Errorf("zero attributor on another root = %v, want %v: knowing no roots means trusting no mismatch", got, AttributedToRootOnly)
	}
}

// TestAttributeNilNodeIsElsewhere keeps a typed nil from acquiring evidence.
func TestAttributeNilNodeIsElsewhere(t *testing.T) {
	attributor := NewRootAttributor([]string{"/ws/api"}, nil)
	if got := attributor.Attribute(nil, "/ws/api"); got != AttributedElsewhere {
		t.Errorf("Attribute(nil node) = %v, want %v", got, AttributedElsewhere)
	}
	if got := attributor.Attribute(nil, ""); got != AttributedElsewhere {
		t.Errorf("Attribute(nil node, empty root) = %v, want %v", got, AttributedElsewhere)
	}
}

// TestNewRootAttributorToleratesAnEmptyRun covers the inputs a caller can
// hand it before it knows anything: no roots, no graph, blank spellings.
func TestNewRootAttributorToleratesAnEmptyRun(t *testing.T) {
	node := sitedNode(t, "left-pad", PackageLocation{ModuleRoot: "/ws/api"})

	for _, tc := range []struct {
		name       string
		attributor RootAttributor
	}{
		{"nil graph", NewRootAttributor([]string{"/ws/web"}, nil)},
		{"no roots", NewRootAttributor(nil, graphOf(t, node))},
		{"blank roots", NewRootAttributor([]string{"", "  "}, graphOf(t, node))},
	} {
		if got := tc.attributor.Attribute(node, "/ws/web"); got != AttributedToRootOnly {
			t.Errorf("%s: Attribute = %v, want %v: an uncalibrated run keeps the evidence", tc.name, got, AttributedToRootOnly)
		}
	}
}

// TestRootAttributionString keeps diagnostics readable; a failure message
// that prints "2" says nothing about what was claimed.
func TestRootAttributionString(t *testing.T) {
	for _, tc := range []struct {
		attribution RootAttribution
		want        string
	}{
		{AttributedElsewhere, "attributed-elsewhere"},
		{AttributedToRootOnly, "attributed-to-root-only"},
		{AttributedToSite, "attributed-to-site"},
		{RootAttribution(7), "root-attribution(7)"},
	} {
		if got := tc.attribution.String(); got != tc.want {
			t.Errorf("RootAttribution(%d).String() = %q, want %q", int(tc.attribution), got, tc.want)
		}
	}
}
