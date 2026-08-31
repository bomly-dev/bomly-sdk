package sdk

import "testing"

// TestFillGapDoesNotCountAnUnpublishableValueAsStated pins the defect the
// class exists for, found in the M1 review and repeated since. An
// unpublishable non-empty value looked "stated", so it blocked a valid
// replacement and was then dropped at encode -- losing both.
func TestFillGapDoesNotCountAnUnpublishableValueAsStated(t *testing.T) {
	publishable := func(s string) bool { return s != "bad" }

	if got := MergeFillGap("bad", "good", publishable); got != "good" {
		t.Errorf("got %q, want the unpublishable value replaced", got)
	}
	if got := MergeFillGap("first", "second", publishable); got != "first" {
		t.Errorf("got %q, want a stated value kept", got)
	}
	if got := MergeFillGap("", "second", publishable); got != "second" {
		t.Errorf("got %q, want the gap filled", got)
	}
	// A replacement that is itself unpublishable does not get in through the
	// gap: the gate applies to both sides.
	if got := MergeFillGap("", "bad", publishable); got != "" {
		t.Errorf("got %q, want an unpublishable replacement refused", got)
	}
	// With no test supplied the rule is a plain gap fill.
	if got := MergeFillGap("bad", "good", nil); got != "bad" {
		t.Errorf("got %q, want the first value with no publishability test", got)
	}
}

// TestUnionNeverReturnsEarly pins the second recurring defect: a merge that
// returns when the incoming side is empty leaves whatever the destination had,
// including a member that would not survive its own gate. The value then stays
// visible in process and vanishes at encode.
func TestUnionNeverReturnsEarly(t *testing.T) {
	key := func(s string) string { return s }
	drop := func(s string) (string, bool) { return s, s != "bad" }

	got := MergeUnion([]string{"good", "bad"}, nil, key, drop)
	if len(got) != 1 || got[0] != "good" {
		t.Errorf("got %v, want the ungated member dropped even with nothing incoming", got)
	}
}

// TestUnionIsSortedAndDeduplicated pins that a document built from a union is
// byte-stable however the two sides were ordered.
func TestUnionIsSortedAndDeduplicated(t *testing.T) {
	key := func(s string) string { return s }

	a := MergeUnion([]string{"zeta", "alpha"}, []string{"mid", "alpha"}, key, nil)
	b := MergeUnion([]string{"mid", "alpha"}, []string{"alpha", "zeta"}, key, nil)
	if len(a) != 3 || a[0] != "alpha" || a[2] != "zeta" {
		t.Errorf("got %v, want three members sorted", a)
	}
	if len(a) != len(b) {
		t.Fatalf("order changed the membership: %v vs %v", a, b)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("order changed the result: %v vs %v", a, b)
			break
		}
	}
	// An empty result is nil, not an empty slice, so it omits from the wire.
	if got := MergeUnion[string](nil, nil, key, nil); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

// TestStrongestIsOrderIndependent pins the property two graphs merged in
// either direction depend on.
func TestStrongestIsOrderIndependent(t *testing.T) {
	rank := func(s string) int {
		if s == "high" {
			return 2
		}
		return 1
	}
	if a, b := MergeStrongest("high", "low", rank), MergeStrongest("low", "high", rank); a != b || a != "high" {
		t.Errorf("got %q and %q, want both to be high", a, b)
	}
	// An unstated value never wins, whichever side it is on.
	if got := MergeStrongest("low", "", rank); got != "low" {
		t.Errorf("got %q, want the stated value", got)
	}
	if got := MergeStrongest("", "low", rank); got != "low" {
		t.Errorf("got %q, want the stated value", got)
	}
	// A tie keeps the current value rather than churning.
	if got := MergeStrongest("low", "other", func(string) int { return 1 }); got != "low" {
		t.Errorf("got %q, want the tie to keep the current value", got)
	}
}

// TestEdgeKindMergeUsesTheStrongestClass pins that the routing actually
// happened: the class is what decides, so a fix to the class reaches the
// field.
func TestEdgeKindMergeUsesTheStrongestClass(t *testing.T) {
	if got := MergeEdgeKind(EdgeKindDescribes, EdgeKindDependsOn); got != EdgeKindDependsOn {
		t.Errorf("got %q, want the dependency claim to win", got)
	}
	if got := MergeEdgeKind(EdgeKindDependsOn, EdgeKindDescribes); got != EdgeKindDependsOn {
		t.Errorf("got %q, want order not to matter", got)
	}
}
