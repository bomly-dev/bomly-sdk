package sdk

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// wireRoots are the payloads serve.go encodes and decodes for bomly.plugin.v1.
//
// Taken from serve.go rather than chosen. A hand-picked root set was one of
// this rule's earlier bugs: it listed thirteen types that seemed reasonable
// and reached a sixth of the wire.
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

// alwaysSentKeys are the wire keys a zero value still emits, by "Type.key".
//
// Keyed by the JSON name rather than the Go field, because the wire is the
// subject and the two differ where it matters: the filter types send
// "Include", capitalised, carrying no tag at all.
//
// Two kinds of entry. Some carry a reason: an identity or discriminator whose
// absence would make the payload unreadable, where zero is still an answer.
// The rest say "grandfathered", which records what is true without claiming it
// was decided. bomly-sdk#78 tracks turning each of those into a reason or a
// marker, and every one it resolves is a key these rules begin guarding.
var alwaysSentKeys = map[string]string{
	// Identity and discriminators: zero is an answer, not an absence.
	"Vulnerability.id":                     "a vulnerability without an ID cannot be referenced",
	"Finding.id":                           "a finding without an ID cannot be referenced",
	"Finding.kind":                         "the discriminator that says how to read the finding",
	"MatcherStats.name":                    "stats that do not say whose they are cannot be attributed",
	"PackageScorecardCheck.name":           "a check without a name cannot be reported",
	"MatcherDescriptor.name":               "a descriptor without a name cannot be routed to",
	"AnalyzerDescriptor.name":              "a descriptor without a name cannot be routed to",
	"DetectorDescriptor.name":              "a descriptor without a name cannot be routed to",
	"AuditorDescriptor.name":               "a descriptor without a name cannot be routed to",
	"PackageManagerSupport.packageManager": "the key the support row is about",
	"DependencyNode.id":                    "the canonical package URL is the node's identity (ADR-0041)",
	"DependencyNode.kind":                  "the sealed union's discriminator (ADR-0041)",
	// Booleans whose whole purpose is the false answer.
	"ReadyResponse.ready":           "false is the answer this response exists to give",
	"ApplicableResponse.applicable": "false is the answer this response exists to give",

	// Grandfathered: recorded, not endorsed. Each is a key a zero value puts
	// on the wire today. Giving one omitempty relaxes the v1 schema, which is
	// a decision for #78, not for the pass that added these rules.
	//
	// The capitalised ones are untagged exported fields, encoded under their
	// Go names. Those need `json:"Include,omitempty"` keeping the capital --
	// tagging one "include" renames the wire field, which is a v1 break
	// wearing the shape of an additive change.
	"AnalyzeRequest.analyzerFilter":                         "grandfathered",
	"AnalyzeRequest.executionTarget":                        "grandfathered",
	"AnalyzeRequest.query":                                  "grandfathered",
	"AnalyzeRequest.subprojectInfo":                         "grandfathered",
	"AnalyzerFilter.Exclude":                                "grandfathered",
	"AnalyzerFilter.Include":                                "grandfathered",
	"AuditRequest.auditorFilter":                            "grandfathered",
	"AuditRequest.executionTarget":                          "grandfathered",
	"AuditRequest.query":                                    "grandfathered",
	"AuditRequest.subprojectInfo":                           "grandfathered",
	"AuditorFilter.Exclude":                                 "grandfathered",
	"AuditorFilter.Include":                                 "grandfathered",
	"CallFrame.position":                                    "grandfathered",
	"CallPath.sink":                                         "grandfathered",
	"DependencyDetailTransition.after":                      "grandfathered",
	"DependencyDetailTransition.afterRegistryEligible":      "grandfathered",
	"DependencyDetailTransition.before":                     "grandfathered",
	"DependencyDetailTransition.beforeRegistryEligible":     "grandfathered",
	"DependencyDetailTransition.changedFields":              "grandfathered",
	"DetectionRequest.detectorFilter":                       "grandfathered",
	"DetectionRequest.executionTarget":                      "grandfathered",
	"DetectionRequest.query":                                "grandfathered",
	"DetectionRequest.subproject":                           "grandfathered",
	"DetectionResult.rootExecutionTarget":                   "grandfathered",
	"DetectionResult.subprojectInfo":                        "grandfathered",
	"DetectorFilter.Exclude":                                "grandfathered",
	"DetectorFilter.Include":                                "grandfathered",
	"DetectorWarning.message":                               "grandfathered",
	"DetectorWarning.type":                                  "grandfathered",
	"EPSSScore.epss":                                        "grandfathered",
	"GraphEntry.manifest":                                   "grandfathered",
	"MatchRequest.executionTarget":                          "grandfathered",
	"MatchRequest.matcherFilter":                            "grandfathered",
	"MatchRequest.query":                                    "grandfathered",
	"MatchRequest.subprojectInfo":                           "grandfathered",
	"MatchResult.matcherStats":                              "grandfathered",
	"MatcherFilter.Exclude":                                 "grandfathered",
	"MatcherFilter.Include":                                 "grandfathered",
	"PackageRemediation.status":                             "grandfathered",
	"PackageRemediationSuggestion.action":                   "grandfathered",
	"PackageRemediationSuggestion.affected_dependency_refs": "grandfathered",
	"PackageScorecard.aggregateScore":                       "grandfathered",
	"PackageScorecard.runDate":                              "grandfathered",
	"PackageScorecardCheck.score":                           "grandfathered",
	"Reachability.status":                                   "grandfathered",
	"ReachabilityEvidence.status":                           "grandfathered",
	"RemediationHint.dependencyRef":                         "grandfathered",
	"RemediationHintRequest.detection":                      "grandfathered",
	"RemediationStrategyHint.action":                        "grandfathered",
	"ResolutionFallback.from":                               "grandfathered",
	"ResolutionMetadata.install_executed":                   "grandfathered",
	"RiskScore.score":                                       "grandfathered",
	"Subproject.executionTarget":                            "grandfathered",
}

// intentionallyRequired are the keys whose FIELD should carry no omitempty:
// the schema says required, and the tag should say so too.
//
// This is a strict subset of alwaysSentKeys, and the difference is the point.
// A key is in alwaysSentKeys when a zero value emits it, which happens for two
// unrelated reasons: the field has no marker, or the field has one and
// encoding/json ignores it because the value is a struct. Only the first is a
// statement about the tag. Treating them alike would exempt every struct-valued
// field from the tag rule, and those are exactly the fields whose marker can be
// dropped without moving a byte -- the regression that started this thread.
var intentionallyRequired = map[string]string{
	"AnalyzeRequest.analyzerFilter":                         "the field carries no marker today",
	"AnalyzeRequest.executionTarget":                        "the field carries no marker today",
	"AnalyzeRequest.query":                                  "the field carries no marker today",
	"AnalyzeRequest.subprojectInfo":                         "the field carries no marker today",
	"AnalyzerDescriptor.name":                               "the field carries no marker today",
	"ApplicableResponse.applicable":                         "the field carries no marker today",
	"AuditRequest.auditorFilter":                            "the field carries no marker today",
	"AuditRequest.executionTarget":                          "the field carries no marker today",
	"AuditRequest.query":                                    "the field carries no marker today",
	"AuditRequest.subprojectInfo":                           "the field carries no marker today",
	"AuditorDescriptor.name":                                "the field carries no marker today",
	"CallPath.sink":                                         "the field carries no marker today",
	"DependencyDetailTransition.after":                      "the field carries no marker today",
	"DependencyDetailTransition.afterRegistryEligible":      "the field carries no marker today",
	"DependencyDetailTransition.before":                     "the field carries no marker today",
	"DependencyDetailTransition.beforeRegistryEligible":     "the field carries no marker today",
	"DependencyDetailTransition.changedFields":              "the field carries no marker today",
	"DetectionRequest.detectorFilter":                       "the field carries no marker today",
	"DetectionRequest.executionTarget":                      "the field carries no marker today",
	"DetectionRequest.query":                                "the field carries no marker today",
	"DetectionRequest.subproject":                           "the field carries no marker today",
	"DetectionResult.rootExecutionTarget":                   "the field carries no marker today",
	"DetectionResult.subprojectInfo":                        "the field carries no marker today",
	"DetectorDescriptor.name":                               "the field carries no marker today",
	"DetectorWarning.message":                               "the field carries no marker today",
	"DetectorWarning.type":                                  "the field carries no marker today",
	"EPSSScore.epss":                                        "the field carries no marker today",
	"Finding.id":                                            "the field carries no marker today",
	"Finding.kind":                                          "the field carries no marker today",
	"GraphEntry.manifest":                                   "the field carries no marker today",
	"MatchRequest.executionTarget":                          "the field carries no marker today",
	"MatchRequest.matcherFilter":                            "the field carries no marker today",
	"MatchRequest.query":                                    "the field carries no marker today",
	"MatchRequest.subprojectInfo":                           "the field carries no marker today",
	"MatcherDescriptor.name":                                "the field carries no marker today",
	"MatcherStats.name":                                     "the field carries no marker today",
	"PackageManagerSupport.packageManager":                  "the field carries no marker today",
	"PackageRemediation.status":                             "the field carries no marker today",
	"PackageRemediationSuggestion.action":                   "the field carries no marker today",
	"PackageRemediationSuggestion.affected_dependency_refs": "the field carries no marker today",
	"PackageScorecard.aggregateScore":                       "the field carries no marker today",
	"PackageScorecardCheck.name":                            "the field carries no marker today",
	"PackageScorecardCheck.score":                           "the field carries no marker today",
	"Reachability.status":                                   "the field carries no marker today",
	"ReachabilityEvidence.status":                           "the field carries no marker today",
	"ReadyResponse.ready":                                   "the field carries no marker today",
	"RemediationHint.dependencyRef":                         "the field carries no marker today",
	"RemediationHintRequest.detection":                      "the field carries no marker today",
	"RemediationStrategyHint.action":                        "the field carries no marker today",
	"ResolutionFallback.from":                               "the field carries no marker today",
	"ResolutionMetadata.install_executed":                   "the field carries no marker today",
	"RiskScore.score":                                       "the field carries no marker today",
	"Subproject.executionTarget":                            "the field carries no marker today",
	"Vulnerability.id":                                      "the field carries no marker today",
}

// A zero value of every type on the v1 wire emits only declared keys.
//
// This asks the encoder, not the struct tags. Four review rounds found four
// ways a field joins the permanent wire, and each earlier fix added another
// shape to a tag-reading rule: a field name nobody enumerated, a type nobody
// enumerated, an exported field with no tag at all, and a struct a custom
// MarshalJSON emits that no tag describes. They are one question -- does a
// zero value put this key on the wire -- and marshalling answers it.
//
// It sees what reflection over tags cannot: DependencyNode reports "id" and
// "kind" through ADR-0041's own encoder, and an untagged field arrives under
// its Go name. A mistyped option needs no special case either, because
// encoding/json ignores the option and the key simply appears.
func TestWireV1ZeroValuesEmitOnlyDeclaredKeys(t *testing.T) {
	types := reachableWireTypes()
	if len(types) < 50 {
		t.Fatalf("the walk reached %d types; it reached 77 when written, so it is no longer following "+
			"the wire and its silence would mean nothing", len(types))
	}

	for _, typ := range types {
		encoded, err := json.Marshal(reflect.New(typ).Interface())
		if err != nil {
			t.Errorf("marshal zero %s: %v", typ.Name(), err)
			continue
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &object); err != nil {
			continue // not a JSON object: a scalar codec has nothing to declare
		}
		for _, key := range sortedKeys(object) {
			if _, declared := alwaysSentKeys[typ.Name()+"."+key]; declared {
				continue
			}
			t.Errorf("a zero %s puts %q on the wire, so consumers read the key as required. Give the "+
				"field omitempty, or declare %q in alwaysSentKeys with the reason it is always sent.",
				typ.Name(), key, typ.Name()+"."+key)
		}
	}
}

// Every JSON-tagged field on the v1 wire declares omitempty, unless
// alwaysSentKeys says why not.
//
// Not redundant with the rule above: the two protect different things and part
// company in one place. That one measures bytes. This measures the declared
// schema, which is what AGENTS.md means by "struct JSON tags *are* the wire
// schema" -- consumers generating a schema by reflection read the tag, not the
// output.
//
// They differ on struct-valued fields, where encoding/json v1 ignores
// omitempty entirely: a struct is never empty, the key is emitted either way,
// and the bytes cannot tell you the marker was dropped. That is exactly the
// regression that opened this thread, and only a tag rule sees it.
func TestWireV1TaggedFieldsDeclareOmitEmpty(t *testing.T) {
	for _, typ := range reachableWireTypes() {
		for i := range typ.NumField() {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}
			tag, tagged := field.Tag.Lookup("json")
			if !tagged {
				continue // untagged: the zero-value rule sees it by its Go name
			}
			name, options, _ := strings.Cut(tag, ",")
			if name == "-" || name == "" {
				continue // not on the wire, or an embed contributing its own fields
			}
			key := typ.Name() + "." + name
			if _, required := intentionallyRequired[key]; required {
				continue
			}
			// Deliberately NOT exempt for being in alwaysSentKeys. A key
			// lands there for two different reasons, and only one of them
			// says anything about the tag: a field the encoder emits
			// regardless -- a struct value, where omitempty is a no-op --
			// still has a marker to lose, and losing it still changes the
			// schema a reflection-based consumer generates. Exempting it
			// here because the bytes cannot see the loss is how that
			// regression walks back in.
			if !hasJSONOption(options, "omitempty") {
				t.Errorf("%s is tagged without omitempty: a consumer generating a schema by reflection "+
					"reads the key as required even where the bytes happen to match. Add omitempty, or "+
					"declare %q in alwaysSentKeys.", key, key)
			}
		}
	}
}

// A declaration for a key nothing emits is a rule nobody is applying, and it
// hides the day that key comes back unguarded.
func TestAlwaysSentKeysAreAllEmitted(t *testing.T) {
	emitted := map[string]bool{}
	for _, typ := range reachableWireTypes() {
		encoded, err := json.Marshal(reflect.New(typ).Interface())
		if err != nil {
			continue
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(encoded, &object) != nil {
			continue
		}
		for key := range object {
			emitted[typ.Name()+"."+key] = true
		}
	}
	for key := range alwaysSentKeys {
		if !emitted[key] {
			t.Errorf("alwaysSentKeys declares %q, which no zero value emits; drop the entry, or the day "+
				"it returns it returns unchecked", key)
		}
	}
}

// reachableWireTypes returns every struct this module defines that is reachable
// from a v1 wire root, roots included.
//
// Reachability is by exported field, through pointer, slice, array and map
// element types. Types from other modules are not followed: their fields are
// not ours to tag, and walking into them would recurse through the standard
// library forever.
func reachableWireTypes() []reflect.Type {
	sdkPackage := reflect.TypeOf(MatchRequest{}).PkgPath()
	visited := map[reflect.Type]bool{}
	var found []reflect.Type

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
		found = append(found, typ)
		for i := range typ.NumField() {
			if field := typ.Field(i); field.IsExported() {
				walk(field.Type)
			}
		}
	}
	for _, root := range wireRoots {
		walk(reflect.TypeOf(root))
	}
	return found
}

func sortedKeys(object map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// hasJSONOption reports whether a json tag's option list contains exactly this
// option.
//
// A substring test asks a different question: "notomitempty" contains
// "omitempty", encoding/json ignores the unknown option, and the field is
// emitted while the substring check calls it optional. Split by hand because
// the standard library keeps its own tag parser unexported and
// reflect.StructTag hands back the raw value, so there is no authority to
// delegate to; the grammar is one comma-separated string.
func hasJSONOption(options, want string) bool {
	for option := range strings.SplitSeq(options, ",") {
		if option == want {
			return true
		}
	}
	return false
}

// The rules are only worth having if they see a key arrive, so exercise them
// on fixtures rather than only on the types they police -- those pass today,
// and a rule that inspected nothing would pass too. Every shape here defeated
// an earlier tag-reading version of this test.
func TestZeroValueRuleSeesEveryWayAKeyArrives(t *testing.T) {
	keysOf := func(value any) []string {
		t.Helper()
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &object); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return sortedKeys(object)
	}

	for _, testCase := range []struct {
		name  string
		value any
		want  []string
	}{
		{"omitempty is honoured", struct {
			A string `json:"a,omitempty"`
		}{}, nil},
		{"a missing marker emits", struct {
			A string `json:"a"`
		}{}, []string{"a"}},
		// staticcheck SA5008 rejects an unknown tag option, which is a
		// stronger guard than this fixture for this one shape: it fails at
		// lint time rather than at test time. The fixture stays anyway,
		// because it pins what the *encoder* does with a malformed option,
		// and a lint rule can be disabled where the wire cannot.
		{"a mistyped marker emits, because encoding/json ignores the option", struct {
			A string `json:"a,notomitempty"` //nolint:staticcheck // the malformed option is the fixture
		}{}, []string{"a"}},
		{"an untagged exported field emits under its Go name", struct {
			A string
		}{}, []string{"A"}},
		{"a dash is not on the wire", struct {
			A string `json:"-"`
		}{}, nil},
	} {
		if got := keysOf(testCase.value); strings.Join(got, ",") != strings.Join(testCase.want, ",") {
			t.Errorf("%s: keys = %v, want %v", testCase.name, got, testCase.want)
		}
	}
}

// The option test, pinned on the near misses that motivate it.
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
