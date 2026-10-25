package plugin

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk/internal/deepcopytest"
)

// TestKnownRequirementsAreWellFormedAndSorted keeps the vocabulary inside
// its own grammar, so every token this SDK defines validates everywhere.
func TestKnownRequirementsAreWellFormedAndSorted(t *testing.T) {
	known := KnownRequirements()
	if !slices.IsSorted(known) {
		t.Errorf("KnownRequirements is not sorted: %v", known)
	}
	if err := Requirements(known).Validate(); err != nil {
		t.Errorf("the SDK's own vocabulary does not validate: %v", err)
	}
	for _, requirement := range known {
		if !requirement.Known() {
			t.Errorf("%q is listed but not Known", requirement)
		}
	}
}

func TestRequirementsNormalizeAndRoundTrip(t *testing.T) {
	declared := Requirements{RequirementVulnerabilityRecords, RequirementSourceTree, "future-input-v2", RequirementSourceTree}
	want := Requirements{"future-input-v2", RequirementSourceTree, RequirementVulnerabilityRecords}
	if got := declared.Normalized(); !slices.Equal(got, want) {
		t.Errorf("Normalized = %v, want %v", got, want)
	}
	if (Requirements{}).Normalized() != nil {
		t.Error("an empty declaration normalizes to non-nil")
	}

	data, err := json.Marshal(declared)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(data) != `["future-input-v2","source-tree-v1","vulnerability-records-v1"]` {
		t.Errorf("encoded %s", data)
	}
	var decoded Requirements
	if err := json.Unmarshal([]byte(`["vulnerability-records-v1","future-input-v2","future-input-v2"]`), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// The unknown token survives: a host must see it to refuse it.
	if !slices.Equal(decoded, Requirements{"future-input-v2", RequirementVulnerabilityRecords}) {
		t.Errorf("decoded %v", decoded)
	}
}

func TestRequirementsValidate(t *testing.T) {
	for _, valid := range []Requirements{
		nil,
		{RequirementSourceTree},
		{"future-input-v2"},
		{"a-v10", "b2-c3-v1"},
	} {
		if err := valid.Validate(); err != nil {
			t.Errorf("Validate(%v) = %v", valid, err)
		}
	}
	tooMany := make(Requirements, MaxRequirements+1)
	for i := range tooMany {
		tooMany[i] = RequirementSourceTree
	}
	for _, invalid := range []Requirements{
		{"source-tree"},
		{"Source-Tree-v1"},
		{"source-tree-v0"},
		{"source_tree-v1"},
		{"plugin:osv-v1"},
		{""},
		{Requirement(strings.Repeat("a", MaxRequirementLength) + "-v1")},
		tooMany,
	} {
		if err := invalid.Validate(); err == nil {
			t.Errorf("Validate(%.40v) accepted a malformed declaration", invalid)
		}
	}
}

// TestRequirementsUnsatisfied: a token the host cannot vouch for -- unknown
// included -- is unsatisfied; a fully met declaration reports nil.
func TestRequirementsUnsatisfied(t *testing.T) {
	declared := Requirements{RequirementSourceTree, RequirementVulnerabilityRecords, "future-input-v2"}
	available := []Requirement{RequirementSourceTree, RequirementDependencyGraph}
	if got, want := declared.Unsatisfied(available), (Requirements{"future-input-v2", RequirementVulnerabilityRecords}); !slices.Equal(got, want) {
		t.Errorf("Unsatisfied = %v, want %v", got, want)
	}
	if got := (Requirements{RequirementSourceTree}).Unsatisfied(available); got != nil {
		t.Errorf("a met declaration reports %v", got)
	}
	if got := Requirements(nil).Unsatisfied(nil); got != nil {
		t.Errorf("a legacy descriptor reports %v", got)
	}
}

// TestDescriptorsCarryRequirements covers every component kind: the
// declaration validates through the kind's gate, rejects a malformed token,
// survives the wire normalized, and clones without aliasing.
func TestDescriptorsCarryRequirements(t *testing.T) {
	requires := Requirements{RequirementVulnerabilityRecords, RequirementSourceTree}
	malformed := Requirements{"needs plugin x"}
	cases := []struct {
		kind     string
		validate func(Requirements) error
		encode   func(Requirements) any
		decode   func([]byte) (Requirements, error)
		clone    func() (source, clone any)
	}{
		{"detector",
			func(r Requirements) error {
				return ValidateDetectorDescriptor(&DetectorDescriptor{Name: "d", Requires: r})
			},
			func(r Requirements) any { return DetectorDescriptor{Name: "d", Requires: r} },
			func(data []byte) (Requirements, error) {
				var d DetectorDescriptor
				err := json.Unmarshal(data, &d)
				return d.Requires, err
			},
			func() (any, any) {
				var d DetectorDescriptor
				deepcopytest.Fill(&d)
				return &d, new(d.Clone())
			}},
		{"matcher",
			func(r Requirements) error {
				return ValidateMatcherDescriptor(&MatcherDescriptor{Name: "m", Requires: r})
			},
			func(r Requirements) any { return MatcherDescriptor{Name: "m", Requires: r} },
			func(data []byte) (Requirements, error) {
				var d MatcherDescriptor
				err := json.Unmarshal(data, &d)
				return d.Requires, err
			},
			func() (any, any) {
				var d MatcherDescriptor
				deepcopytest.Fill(&d)
				return &d, new(d.Clone())
			}},
		{"auditor",
			func(r Requirements) error {
				return ValidateAuditorDescriptor(&AuditorDescriptor{Name: "a", Requires: r})
			},
			func(r Requirements) any { return AuditorDescriptor{Name: "a", Requires: r} },
			func(data []byte) (Requirements, error) {
				var d AuditorDescriptor
				err := json.Unmarshal(data, &d)
				return d.Requires, err
			},
			func() (any, any) {
				var d AuditorDescriptor
				deepcopytest.Fill(&d)
				return &d, new(d.Clone())
			}},
		{"analyzer",
			func(r Requirements) error {
				return ValidateAnalyzerDescriptor(&AnalyzerDescriptor{Name: "z", Requires: r})
			},
			func(r Requirements) any { return AnalyzerDescriptor{Name: "z", Requires: r} },
			func(data []byte) (Requirements, error) {
				var d AnalyzerDescriptor
				err := json.Unmarshal(data, &d)
				return d.Requires, err
			},
			func() (any, any) {
				var d AnalyzerDescriptor
				deepcopytest.Fill(&d)
				return &d, new(d.Clone())
			}},
	}
	for _, c := range cases {
		t.Run(c.kind, func(t *testing.T) {
			if err := c.validate(requires); err != nil {
				t.Errorf("valid requirements rejected: %v", err)
			}
			if err := c.validate(malformed); err == nil {
				t.Error("a malformed requirement passed the descriptor gate")
			}
			data, err := json.Marshal(c.encode(requires))
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			got, err := c.decode(data)
			if err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if !slices.Equal(got, requires.Normalized()) {
				t.Errorf("round trip = %v, want %v", got, requires.Normalized())
			}
			// A v1 descriptor that predates the field decodes as legacy.
			legacy, err := c.decode([]byte(`{"name":"old"}`))
			if err != nil || legacy != nil {
				t.Errorf("a descriptor without requires decodes as %v, %v; want nil", legacy, err)
			}
			source, clone := c.clone()
			for _, alias := range deepcopytest.Aliases(source, clone) {
				t.Errorf("descriptor clone aliases its source at %s", alias)
			}
		})
	}
}

// FuzzRequirements holds the declaration codec to its contract on arbitrary
// descriptor input: no panic, and what it decodes re-encodes to a fixed
// point that keeps every entry it read.
func FuzzRequirements(f *testing.F) {
	for _, seed := range []string{`[]`, `["source-tree-v1","source-tree-v1"]`, `["future-input-v2","dependency-graph-v1"]`, `["Bad Token",""]`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		var decoded Requirements
		if err := json.Unmarshal(data, &decoded); err != nil {
			return
		}
		first, err := json.Marshal(decoded)
		if err != nil {
			t.Fatal(err)
		}
		var again Requirements
		if err := json.Unmarshal(first, &again); err != nil {
			t.Fatalf("decode own output %s: %v", first, err)
		}
		if !slices.Equal(decoded, again) {
			t.Fatalf("not a fixed point: %v vs %v", decoded, again)
		}
	})
}
