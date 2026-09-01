package sdk

import "testing"

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
