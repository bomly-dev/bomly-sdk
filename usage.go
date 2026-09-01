package sdk

import (
	"sort"
	"strings"
)

// A package's scope and directness are properties of a *site*, not of the
// package. In a workspace the same version can be a direct development
// dependency of one module and a transitive runtime dependency of another,
// and a node that carries only the union of those cannot answer either
// question: "reachable and runtime and direct" is true of the union while
// being true of no single usage.
//
// So attribution lives on PackageLocation, the node-level values become a
// derived union over the sites, and the conjunctive filter below joins
// reachability evidence to locations within one module root -- which is the
// only place the conjunction is a statement about something real.
//
// Producers migrate separately: until detectors record per-site attribution
// and analyzers emit per-module-root evidence, these fields are empty and
// every derivation below falls back to the node-level values. That fallback
// is why this is additive rather than a break.

// LocationScopes returns the union of the scopes recorded across a node's
// locations, sorted and deduplicated. It returns nil when no location carries
// attribution, which is what a producer that has not migrated yet leaves.
func (n *DependencyNode) LocationScopes() []Scope {
	if n == nil {
		return nil
	}
	var union []Scope
	for _, location := range n.Locations {
		for _, scope := range location.Scopes {
			if scope == ScopeUnknown || containsScope(union, scope) {
				continue
			}
			union = append(union, scope)
		}
	}
	sort.Slice(union, func(i, j int) bool { return union[i] < union[j] })
	return union
}

// AttributedScopes is the node's scope set, preferring the union over its
// locations when the sites carry attribution and falling back to the stored
// node-level set when they do not.
//
// This is the direction the model is moving: the node-level set is a cache of
// what the sites say, not an independent claim. Reading through this rather
// than Scopes directly means a caller keeps working both before and after the
// producers migrate.
func (n *DependencyNode) AttributedScopes() []Scope {
	if n == nil {
		return nil
	}
	if union := n.LocationScopes(); len(union) > 0 {
		return union
	}
	return append([]Scope(nil), n.Scopes...)
}

// SyncScopesFromLocations rewrites the node-level scope set from its
// locations, so the cache matches what the sites say. It does nothing when no
// location carries scopes, which keeps it safe to call on a graph whose
// producers have not migrated -- rather than emptying a set that is the only
// record there is.
func (n *DependencyNode) SyncScopesFromLocations() {
	if n == nil {
		return
	}
	if union := n.LocationScopes(); len(union) > 0 {
		n.Scopes = union
	}
}

// ReachabilityEvidence is one analyzer's finding for one vulnerability within
// one module root.
//
// Reachability is a per-module-root question for the same reason scope is: a
// vulnerable symbol can be called from one workspace member and unused by
// another, and one status for the whole scan cannot say so. Vulnerability's
// Reachability annotation becomes the derived summary over these.
type ReachabilityEvidence struct {
	// ModuleRoot is the module this finding is about. Empty means the
	// analyzer did not attribute it, which is a whole-scan claim.
	ModuleRoot string `json:"module_root,omitempty"`
	// DependencyRefs optionally names the exact occurrence nodes the analyzer
	// could attribute the finding to, by node ID. Empty means the analyzer
	// could not narrow it below the module root, which is the common case --
	// so a consumer must treat it as "not stated", never as "no occurrence".
	DependencyRefs []string `json:"dependency_refs,omitempty"`

	Status                 ReachabilityStatus     `json:"status"`
	Tier                   ReachabilityTier       `json:"tier,omitempty"`
	Analyzer               string                 `json:"analyzer,omitempty"`
	Reason                 string                 `json:"reason,omitempty"`
	Symbols                []AffectedSymbol       `json:"symbols,omitempty"`
	CallPaths              []CallPath             `json:"call_paths,omitempty"`
	Hops                   *int                   `json:"hops,omitempty"`
	Confidence             ReachabilityConfidence `json:"confidence,omitempty"`
	DynamicImportsDetected bool                   `json:"dynamic_imports_detected,omitempty"`
	AnalyzedAt             string                 `json:"analyzed_at,omitempty"`
}

// Clone returns a deep copy of the evidence.
func (e ReachabilityEvidence) Clone() ReachabilityEvidence {
	clone := e
	if len(e.DependencyRefs) > 0 {
		clone.DependencyRefs = append([]string(nil), e.DependencyRefs...)
	}
	if len(e.Symbols) > 0 {
		clone.Symbols = make([]AffectedSymbol, 0, len(e.Symbols))
		for _, symbol := range e.Symbols {
			clone.Symbols = append(clone.Symbols, symbol.Clone())
		}
	}
	if len(e.CallPaths) > 0 {
		clone.CallPaths = make([]CallPath, 0, len(e.CallPaths))
		for _, path := range e.CallPaths {
			clone.CallPaths = append(clone.CallPaths, path.Clone())
		}
	}
	if e.Hops != nil {
		hops := *e.Hops
		clone.Hops = &hops
	}
	return clone
}

// DeriveReachability summarizes per-module-root evidence into the single
// annotation a vulnerability carries.
//
// The rule is asymmetric on purpose, because the two answers are not equally
// safe to be wrong about. One module root reaching the symbol makes the
// finding reachable, whatever the others found: a real call path is not
// cancelled by an absence elsewhere. Unreachable requires every piece of
// evidence to say so, and at least one to exist -- anything less is unknown,
// not safe. This is the same caution the tier-3 caveat states in prose:
// "unreachable" is a claim about what was analyzed, not about the world.
//
// The summary keeps the strongest reachable evidence's detail (tier, symbols,
// call paths, hops), since that is the finding a reader needs to act on.
func DeriveReachability(evidence []ReachabilityEvidence) Reachability {
	if len(evidence) == 0 {
		return Reachability{Status: ReachabilityUnknown}
	}
	var best *ReachabilityEvidence
	unreachable := 0
	for i := range evidence {
		switch evidence[i].Status {
		case ReachabilityReachable:
			if best == nil || tierPrecision(evidence[i].Tier) > tierPrecision(best.Tier) {
				best = &evidence[i]
			}
		case ReachabilityUnreachable:
			unreachable++
		}
	}
	if best != nil {
		summary := best.Clone()
		return Reachability{
			Status:                 ReachabilityReachable,
			Tier:                   summary.Tier,
			Analyzer:               summary.Analyzer,
			Reason:                 summary.Reason,
			Symbols:                summary.Symbols,
			CallPaths:              summary.CallPaths,
			Hops:                   summary.Hops,
			Confidence:             summary.Confidence,
			DynamicImportsDetected: summary.DynamicImportsDetected,
			AnalyzedAt:             summary.AnalyzedAt,
		}
	}
	// Every piece of evidence must say unreachable -- not merely every piece
	// that said something. A module the analyzer could not process reports
	// unknown, and counting only the decided ones would let one analyzed
	// module speak for a workspace, turning "we did not look there" into
	// "it is not reachable there". That is the one direction where being
	// wrong is unsafe.
	if unreachable == len(evidence) {
		summary := evidence[0].Clone()
		return Reachability{
			Status:     ReachabilityUnreachable,
			Tier:       summary.Tier,
			Analyzer:   summary.Analyzer,
			Reason:     summary.Reason,
			Confidence: summary.Confidence,
			AnalyzedAt: summary.AnalyzedAt,
		}
	}
	// Nothing was decided. The summary carries an *unknown* item's
	// explanation, not simply the first item's: in a mixed set the first
	// entry can be an unreachable one, and reporting "package-not-imported"
	// as the reason the aggregate is unknown both misstates it and makes the
	// diagnostic depend on slice order. The reason is the whole content of an
	// unknown result -- "missing-toolchain" is actionable where a bare
	// unknown is not -- so it has to come from an item that actually is
	// unknown.
	// An unknown item that explains itself is preferred over one that does
	// not. Taking simply the first unknown was still order-dependent: two
	// module roots both unknown, the first with no reason and the second with
	// "missing-toolchain", produced a bare unknown that changed if the
	// evidence was reordered. The order of preference is: an unknown item
	// with a reason, then any unknown item, then the first item -- each step
	// only reached when the one before it found nothing.
	chosen := evidence[0]
	for i := range evidence {
		if evidence[i].Status != ReachabilityUnknown {
			continue
		}
		if strings.TrimSpace(evidence[i].Reason) != "" {
			chosen = evidence[i]
			break
		}
		if chosen.Status != ReachabilityUnknown {
			chosen = evidence[i]
		}
	}
	summary := chosen.Clone()
	// Trimmed on the way out, not only when choosing. The preference above
	// used TrimSpace to decide which item explained itself, but returned the
	// reason verbatim -- so a set whose only reasons were whitespace
	// published "   " as an explanation, and reversing the evidence published
	// "" instead. What is not an explanation must not read as one.
	summary.Reason = strings.TrimSpace(summary.Reason)
	return Reachability{
		Status:     ReachabilityUnknown,
		Tier:       summary.Tier,
		Analyzer:   summary.Analyzer,
		Reason:     summary.Reason,
		Confidence: summary.Confidence,
		AnalyzedAt: summary.AnalyzedAt,
	}
}

// tierPrecision orders the tiers so the most precise evidence wins a summary.
func tierPrecision(tier ReachabilityTier) int {
	switch tier {
	case TierSymbol:
		return 2
	case TierPackage:
		return 1
	default:
		return 0
	}
}

// UsageFilter is a conjunction of conditions about one usage of a package.
//
// The zero value matches every usage. A condition left empty is not asked.
type UsageFilter struct {
	// Scope, when set, requires the usage's site to carry it.
	Scope Scope
	// Relationship, when set, requires the site to have it.
	Relationship DependencyRelationship
	// Reachable, when true, requires reachability evidence for the usage's
	// module root that says reachable.
	Reachable bool
}

// Usage is one site of a package, with the reachability evidence that applies
// to it. It is what a conjunctive question is actually about.
type Usage struct {
	// ModuleRoot is the module this usage belongs to.
	ModuleRoot string
	// Location is the site itself.
	Location PackageLocation
	// Evidence is the reachability finding for this module root, or nil when
	// there is none.
	Evidence *ReachabilityEvidence
}

// SelectUsages joins a node's locations to reachability evidence within each
// module root and returns the usages matching every condition in the filter.
//
// This is the whole point of per-site attribution. Asking "reachable and
// runtime and direct" of a node's unions can answer yes when no single usage
// satisfies all three -- reachable in one module, runtime in another, direct
// in a third. Joining first and filtering after makes the answer a statement
// about a usage that exists.
//
// Evidence with no module root applies to every location, since a whole-scan
// claim is a claim about all of them. A location with no module root is
// matched only by such evidence: an unattributed site cannot be joined to one
// module's finding without inventing the attribution the producer omitted.
func SelectUsages(node *DependencyNode, evidence []ReachabilityEvidence, filter UsageFilter) []Usage {
	if node == nil {
		return nil
	}
	byRoot := map[string]*ReachabilityEvidence{}
	var global *ReachabilityEvidence
	for i := range evidence {
		if evidence[i].ModuleRoot == "" {
			if global == nil || tierPrecision(evidence[i].Tier) > tierPrecision(global.Tier) {
				global = &evidence[i]
			}
			continue
		}
		existing, ok := byRoot[evidence[i].ModuleRoot]
		if !ok || tierPrecision(evidence[i].Tier) > tierPrecision(existing.Tier) {
			byRoot[evidence[i].ModuleRoot] = &evidence[i]
		}
	}

	var usages []Usage
	for _, location := range node.Locations {
		found := global
		if location.ModuleRoot != "" {
			if scoped, ok := byRoot[location.ModuleRoot]; ok {
				found = scoped
			}
		}
		if filter.Scope != ScopeUnknown && !containsScope(location.Scopes, filter.Scope) {
			continue
		}
		if filter.Relationship != "" && location.Relationship != filter.Relationship {
			continue
		}
		if filter.Reachable && (found == nil || found.Status != ReachabilityReachable) {
			continue
		}
		usages = append(usages, Usage{
			ModuleRoot: location.ModuleRoot,
			Location:   location,
			Evidence:   found,
		})
	}
	return usages
}
