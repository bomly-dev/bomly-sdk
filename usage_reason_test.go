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
