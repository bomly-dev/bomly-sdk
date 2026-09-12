package sdk

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// wireRoots are the payloads serve.go encodes and decodes for bomly.plugin.v1.
//
// Taken from serve.go rather than chosen, because a hand-picked root set is
// the bug this test was rewritten to fix: the first version listed thirteen
// types it seemed reasonable to check and reached a sixth of the wire.
var wireRoots = []any{
	MatchRequest{}, MatchResponse{},
	AnalyzeRequest{}, AnalyzeResponse{},
	DetectRequest{}, DetectResponse{},
	AuditRequest{}, AuditResponse{},
	ReadyResponse{}, ApplicableResponse{}, InstallResponse{},
	RemediationHintRequest{}, RemediationHintResponse{},
	MatcherDescriptor{}, AnalyzerDescriptor{},
	DetectorDescriptor{}, AuditorDescriptor{},
}

// requiredWireFields are the v1 fields sent even when zero, keyed "Type.Field".
//
// Two kinds of entry, and the difference is deliberate. Some carry a reason:
// an identity or a discriminator whose absence would make the payload
// unreadable, where the zero value is still an answer. The rest say
// "grandfathered", which records what is true without claiming it was
// decided -- they predate the rule and were found by this test's first run,
// not introduced by it. Adding omitempty to any of them relaxes the wire
// schema, which is a change this pass is not the place to make. bomly-sdk#78
// tracks turning each grandfathered line into a reason or a marker.
//
// New entries should be rare and each should carry a real reason. A list of
// exemptions is something a reviewer watches grow; that only works while the
// list means something.
var requiredWireFields = map[string]string{
	// Identity and discriminators: the zero value is an answer, not an absence.
	"Vulnerability.ID":                     "a vulnerability without an ID cannot be referenced",
	"Finding.ID":                           "a finding without an ID cannot be referenced",
	"Finding.Kind":                         "the discriminator that says how to read the finding",
	"MatcherStats.Name":                    "stats that do not say whose they are cannot be attributed",
	"PackageScorecardCheck.Name":           "a check without a name cannot be reported",
	"MatcherDescriptor.Name":               "a descriptor without a name cannot be routed to",
	"AnalyzerDescriptor.Name":              "a descriptor without a name cannot be routed to",
	"DetectorDescriptor.Name":              "a descriptor without a name cannot be routed to",
	"AuditorDescriptor.Name":               "a descriptor without a name cannot be routed to",
	"PackageManagerSupport.PackageManager": "the key the support row is about",
	// Booleans whose whole purpose is the false answer.
	"ReadyResponse.Ready":           "false is the answer this response exists to give",
	"ApplicableResponse.Applicable": "false is the answer this response exists to give",

	// Untagged and therefore encoded under their Go names, always present:
	// MatcherFilter went out as {"Include":null,"Exclude":null}. Left alone
	// deliberately -- tagging them `json:"include,omitempty"` would rename
	// the wire field from Include to include, which is a v1 break, not the
	// additive change it looks like. The compatible fix keeps the capital:
	// `json:"Include,omitempty"`. That is still a decision, and #78 has it.
	"MatcherFilter.Include":  "grandfathered: untagged, encoded as \"Include\"",
	"MatcherFilter.Exclude":  "grandfathered: untagged, encoded as \"Exclude\"",
	"AnalyzerFilter.Include": "grandfathered: untagged, encoded as \"Include\"",
	"AnalyzerFilter.Exclude": "grandfathered: untagged, encoded as \"Exclude\"",
	"DetectorFilter.Include": "grandfathered: untagged, encoded as \"Include\"",
	"DetectorFilter.Exclude": "grandfathered: untagged, encoded as \"Exclude\"",
	"AuditorFilter.Include":  "grandfathered: untagged, encoded as \"Include\"",
	"AuditorFilter.Exclude":  "grandfathered: untagged, encoded as \"Exclude\"",

	// Grandfathered: recorded, not endorsed. See bomly-sdk#78.
	"MatchRequest.ExecutionTarget":                        "grandfathered",
	"MatchRequest.SubprojectInfo":                         "grandfathered",
	"MatchRequest.Query":                                  "grandfathered",
	"MatchRequest.MatcherFilter":                          "grandfathered",
	"AnalyzeRequest.ExecutionTarget":                      "grandfathered",
	"AnalyzeRequest.SubprojectInfo":                       "grandfathered",
	"AnalyzeRequest.Query":                                "grandfathered",
	"AnalyzeRequest.AnalyzerFilter":                       "grandfathered",
	"DetectionRequest.ExecutionTarget":                    "grandfathered",
	"DetectionRequest.Subproject":                         "grandfathered",
	"DetectionRequest.DetectorFilter":                     "grandfathered",
	"DetectionRequest.Query":                              "grandfathered",
	"DetectionResult.SubprojectInfo":                      "grandfathered",
	"DetectionResult.RootExecutionTarget":                 "grandfathered",
	"AuditRequest.ExecutionTarget":                        "grandfathered",
	"AuditRequest.SubprojectInfo":                         "grandfathered",
	"AuditRequest.Query":                                  "grandfathered",
	"AuditRequest.AuditorFilter":                          "grandfathered",
	"Subproject.ExecutionTarget":                          "grandfathered",
	"EPSSScore.EPSS":                                      "grandfathered",
	"Reachability.Status":                                 "grandfathered",
	"ReachabilityEvidence.Status":                         "grandfathered",
	"CallPath.Sink":                                       "grandfathered",
	"PackageScorecard.AggregateScore":                     "grandfathered",
	"PackageScorecardCheck.Score":                         "grandfathered",
	"PackageRemediation.Status":                           "grandfathered",
	"PackageRemediationSuggestion.AffectedDependencyRefs": "grandfathered",
	"PackageRemediationSuggestion.Action":                 "grandfathered",
	"GraphEntry.Manifest":                                 "grandfathered",
	"ResolutionMetadata.InstallExecuted":                  "grandfathered",
	"ResolutionFallback.From":                             "grandfathered",
	"DetectorWarning.Type":                                "grandfathered",
	"DetectorWarning.Message":                             "grandfathered",
	"DependencyDetailTransition.Before":                   "grandfathered",
	"DependencyDetailTransition.After":                    "grandfathered",
	"DependencyDetailTransition.ChangedFields":            "grandfathered",
	"DependencyDetailTransition.BeforeRegistryEligible":   "grandfathered",
	"DependencyDetailTransition.AfterRegistryEligible":    "grandfathered",
	"RiskScore.Score":                                     "grandfathered",
	"RemediationHintRequest.Detection":                    "grandfathered",
	"RemediationHint.DependencyRef":                       "grandfathered",
	"RemediationStrategyHint.Action":                      "grandfathered",
}

// hasJSONOption reports whether a json tag's option list contains exactly this
// option.
//
// A substring test is not the same question: "notomitempty" contains
// "omitempty", and encoding/json ignores the unknown option, so the field is
// emitted while a substring check calls it optional. A mistyped tag would then
// change the wire schema with this guard reporting nothing -- the exact
// failure this file exists to prevent, in the file that prevents it.
//
// Split by hand because the standard library keeps its own tag parser
// (encoding/json's tagOptions) unexported, and reflect.StructTag only hands
// back the raw value. There is no authority to delegate to for the option
// list, and the grammar is one comma-separated string.
func hasJSONOption(options, want string) bool {
	for option := range strings.SplitSeq(options, ",") {
		if option == want {
			return true
		}
	}
	return false
}

// ownsItsEncoding reports whether a type marshals itself, in which case its
// struct tags describe nothing: the wire shape is whatever MarshalJSON emits.
// DependencyNode is the case that matters here -- ADR-0041 gives it a codec of
// its own, so its untagged fields never reach the wire under their Go names.
func ownsItsEncoding(typ reflect.Type) bool {
	marshaler := reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	return typ.Implements(marshaler) || reflect.PointerTo(typ).Implements(marshaler)
}

// Every JSON-tagged field on every type reachable from a v1 wire root carries
// omitempty, unless requiredWireFields says why not.
//
// AGENTS.md: "struct JSON tags *are* the wire schema. New fields must be
// optional and tagged omitempty." A dropped marker is therefore a schema
// change even when the encoded bytes are identical, because a consumer
// generating a schema by reflection reads the tag, not the output.
//
// Reachability is the point. The guard this replaces enumerated field names,
// so a field nobody listed went unchecked; the version after that enumerated
// types, so a field on an unlisted type went unchecked -- the same hole moved
// one level up, which is how it survived being "fixed" once. Walking from the
// payloads serve.go actually serializes leaves nowhere for a wire field to be
// added unseen: nested structs, embedded structs, and slice, map and pointer
// element types are all followed.
func TestWireV1ReachableFieldsCarryOmitEmpty(t *testing.T) {
	sdkPackage := reflect.TypeOf(MatchRequest{}).PkgPath()
	visited := map[reflect.Type]bool{}

	var walk func(reflect.Type)
	walk = func(typ reflect.Type) {
		for {
			switch typ.Kind() {
			case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
				typ = typ.Elem()
				continue
			}
			break
		}
		// Only this module's types: a stdlib struct's fields are not ours
		// to tag, and walking into them would report time.Time forever.
		if typ.Kind() != reflect.Struct || typ.PkgPath() != sdkPackage || visited[typ] {
			return
		}
		visited[typ] = true

		for i := range typ.NumField() {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}
			walk(field.Type)

			tag, tagged := field.Tag.Lookup("json")
			if !tagged {
				// An exported field with no tag is still encoded, under
				// its Go name, with no zero-value omission: MatcherFilter
				// went out as {"Include":null,"Exclude":null}. Untagged is
				// not the same as unexposed, and skipping these is how a
				// field joins the permanent wire without any rule seeing
				// it. Types with their own MarshalJSON are exempt --
				// their tags are not the schema, their marshaller is.
				if field.Anonymous || ownsItsEncoding(typ) {
					continue
				}
				key := typ.Name() + "." + field.Name
				if _, exempt := requiredWireFields[key]; exempt {
					continue
				}
				t.Errorf("%s is an exported wire field with no json tag: it is encoded as %q and never "+
					"omitted. Tag it with omitempty, or add %q to requiredWireFields with the reason.",
					key, field.Name, key)
				continue
			}
			if tag == "-" || strings.HasPrefix(tag, "-,") {
				continue
			}
			name, options, _ := strings.Cut(tag, ",")
			if name == "" && field.Anonymous {
				// An embedded struct contributes its own fields, which the
				// walk above reaches directly; the embed carries no name.
				continue
			}
			key := typ.Name() + "." + field.Name
			if reason, exempt := requiredWireFields[key]; exempt {
				if hasJSONOption(options, "omitempty") {
					t.Errorf("%s is listed as always sent (%s) but carries omitempty; "+
						"the list and the tag disagree, so one of them is wrong", key, reason)
				}
				continue
			}
			if !hasJSONOption(options, "omitempty") {
				t.Errorf("%s is a v1 wire field without omitempty: the tag is the wire schema, so a "+
					"consumer generating one by reflection now reads it as required. Add omitempty, or "+
					"add %q to requiredWireFields with the reason it is always sent.", key, key)
			}
		}
	}

	for _, root := range wireRoots {
		walk(reflect.TypeOf(root))
	}

	// A walk that reached almost nothing would pass this test in silence,
	// which is precisely how the previous two versions looked healthy.
	if len(visited) < 50 {
		t.Errorf("the walk reached only %d types; it reached 79 when written, so it is no longer "+
			"following the wire and its silence means nothing", len(visited))
	}
}

// An exemption naming a type or field that no longer exists is a rule nobody
// is applying -- and it hides the day that field comes back without a marker.
func TestRequiredWireFieldsAreAllReachable(t *testing.T) {
	sdkPackage := reflect.TypeOf(MatchRequest{}).PkgPath()
	present := map[string]bool{}
	visited := map[reflect.Type]bool{}

	var walk func(reflect.Type)
	walk = func(typ reflect.Type) {
		for {
			switch typ.Kind() {
			case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
				typ = typ.Elem()
				continue
			}
			break
		}
		if typ.Kind() != reflect.Struct || typ.PkgPath() != sdkPackage || visited[typ] {
			return
		}
		visited[typ] = true
		for i := range typ.NumField() {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}
			present[typ.Name()+"."+field.Name] = true
			walk(field.Type)
		}
	}
	for _, root := range wireRoots {
		walk(reflect.TypeOf(root))
	}

	for key := range requiredWireFields {
		if !present[key] {
			t.Errorf("requiredWireFields exempts %q, which is not reachable from any v1 wire root; "+
				"drop the entry, or the day it returns it returns unchecked", key)
		}
	}
}

// The option test itself, pinned on the shapes that motivated it. A rule about
// exact matching is worth nothing if nobody has seen it reject a near miss.
func TestJSONOptionMatchingIsExact(t *testing.T) {
	for _, testCase := range []struct {
		options string
		want    bool
		why     string
	}{
		{"omitempty", true, "the option alone"},
		{"string,omitempty", true, "after another option"},
		{"omitempty,string", true, "before another option"},
		{"", false, "no options at all"},
		{"string", false, "a different option"},
		{"notomitempty", false, "encoding/json ignores this, so the field is emitted"},
		{"omitemptyish", false, "a longer option that starts the same way"},
		{"omitzero", false, "the neighbouring option, which means something else"},
	} {
		if got := hasJSONOption(testCase.options, "omitempty"); got != testCase.want {
			t.Errorf("hasJSONOption(%q) = %v, want %v -- %s", testCase.options, got, testCase.want, testCase.why)
		}
	}
}
