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
	if mixed.Status != ReachabilityUnknown || mixed.Reason == "" {
		t.Errorf("mixed summary = %+v, want unknown with a reason", mixed)
	}
	// No evidence at all has nothing to explain.
	if got := DeriveReachability(nil); got.Status != ReachabilityUnknown || got.Reason != "" {
		t.Errorf("empty evidence gave %+v", got)
	}
}
