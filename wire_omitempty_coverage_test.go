package sdk

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// requiredWireFields are the v1 payload fields deliberately sent even when
// zero, keyed as "Type.Field".
//
// The list is inverted on purpose. TestWireV1NewFieldsAreOmitEmpty enumerates
// the field names it forbids, so a field nobody adds to that list is not
// checked at all -- AGENTS.md says as much, and the go1.27 modernizer pass
// proved it by deleting omitempty from three exported wire fields with every
// test green. A list of what is checked is a list somebody has to remember;
// a list of what is exempt is a list a reviewer sees grow.
//
// Adding an entry here means asserting that consumers should treat the field
// as always present. That is a wire decision, so it should be an edit someone
// argues for rather than a silence.
var requiredWireFields = map[string]string{
	"MatcherDescriptor.Name":  "a descriptor without a name cannot be routed to",
	"AnalyzerDescriptor.Name": "a descriptor without a name cannot be routed to",
	"DetectorDescriptor.Name": "a descriptor without a name cannot be routed to",
	"AuditorDescriptor.Name":  "a descriptor without a name cannot be routed to",

	// Grandfathered. These predate the rule and were found by this test on
	// its first run, not introduced by it. They are recorded as they are,
	// which is not the same as endorsed: adding omitempty to any of them is
	// a wire change, and a wire change does not belong in a modernizer pass.
	//
	// Worth a deliberate look of their own -- the request fields plausibly
	// are always sent, and AggregateScore plausibly means something at zero,
	// but "plausibly" is the reason this list exists rather than a silence.
	// See bomly-sdk#78.
	"MatchRequest.ExecutionTarget":    "grandfathered: sent on every request today",
	"MatchRequest.SubprojectInfo":     "grandfathered: sent on every request today",
	"MatchRequest.Query":              "grandfathered: sent on every request today",
	"MatchRequest.MatcherFilter":      "grandfathered: sent on every request today",
	"AnalyzeRequest.ExecutionTarget":  "grandfathered: sent on every request today",
	"AnalyzeRequest.SubprojectInfo":   "grandfathered: sent on every request today",
	"AnalyzeRequest.Query":            "grandfathered: sent on every request today",
	"AnalyzeRequest.AnalyzerFilter":   "grandfathered: sent on every request today",
	"PackageScorecard.AggregateScore": "grandfathered: a zero score is a score, not an absence",
}

// Every JSON-tagged field on a v1 wire payload carries omitempty unless it is
// listed above.
//
// AGENTS.md: "struct JSON tags *are* the wire schema. New fields must be
// optional and tagged omitempty." That makes a dropped marker a schema change
// even when the encoded bytes are identical, because schema-driven consumers
// read the tag, not the output -- a field that loses omitempty reads as
// required to anything generating a schema from reflection.
//
// Checked by reflection rather than by name so the rule covers fields nobody
// thought to enumerate, which is exactly where it failed before.
func TestWireV1PayloadFieldsCarryOmitEmpty(t *testing.T) {
	payloads := []any{
		MatchRequest{}, MatchResult{},
		AnalyzeRequest{}, AnalyzeResult{},
		MatcherDescriptor{}, AnalyzerDescriptor{},
		DetectorDescriptor{}, AuditorDescriptor{},
		DependencyNode{}, Package{},
		DocumentAssertions{}, DocumentSource{},
		PackageScorecard{},
	}
	for _, payload := range payloads {
		typ := reflect.TypeOf(payload)
		for i := range typ.NumField() {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}
			tag, ok := field.Tag.Lookup("json")
			if !ok || tag == "-" || strings.HasPrefix(tag, "-,") {
				continue
			}
			name, options, _ := strings.Cut(tag, ",")
			if name == "" && field.Anonymous {
				// An embedded struct's own fields are reached through
				// their own type; the embed itself carries no wire name.
				continue
			}
			key := typ.Name() + "." + field.Name
			if reason, exempt := requiredWireFields[key]; exempt {
				if strings.Contains(options, "omitempty") {
					t.Errorf("%s is listed as always sent (%s) but carries omitempty; "+
						"drop one of the two, they disagree", key, reason)
				}
				continue
			}
			if !strings.Contains(options, "omitempty") {
				t.Errorf("%s is a v1 wire field without omitempty: the tag is the wire schema, so a "+
					"consumer generating one from reflection now reads it as required. Add omitempty, "+
					"or add %q to requiredWireFields with the reason it is always sent.", key, key)
			}
		}
	}
}

// The predicate above is only worth having if it sees a missing marker, so
// pin it on a fixture rather than on the types it polices -- those pass today
// and would pass a rule that inspected nothing.
func TestOmitEmptyCoverageSeesAMissingMarker(t *testing.T) {
	type fixture struct {
		Kept    string    `json:"kept,omitempty"`
		Dropped time.Time `json:"dropped"`
		Ignored string    `json:"-"`
		unexpo  string    //nolint:unused // exercises the unexported skip
	}

	var missing []string
	typ := reflect.TypeOf(fixture{})
	for i := range typ.NumField() {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		tag, ok := field.Tag.Lookup("json")
		if !ok || tag == "-" {
			continue
		}
		if _, options, _ := strings.Cut(tag, ","); !strings.Contains(options, "omitempty") {
			missing = append(missing, field.Name)
		}
	}
	if len(missing) != 1 || missing[0] != "Dropped" {
		t.Errorf("walk reported %v; want exactly [Dropped] -- Kept has the marker, Ignored is not on the "+
			"wire, and the unexported field is not addressable by a consumer", missing)
	}
}
