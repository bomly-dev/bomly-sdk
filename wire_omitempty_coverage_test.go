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

	// The structs a custom MarshalJSON emits, registered because nothing
	// reaches them by exported field. Graph holds its nodes and edges
	// unexported and encodes them through graphJSON, so a zero Graph emits
	// {} and the walk sees nothing -- while a populated one puts every
	// nodeWire and DependencyEdge key on the wire. Naming them here is
	// possible because this test lives in package sdk; a consumer could not
	// write this rule, which is the argument for it living in the SDK.
	graphJSON{}, nodeWire{}, DependencyEdge{},
}

// alwaysSentKeys are the wire keys a zero value still emits, by "Type.key".
//
// Keyed by the JSON name rather than the Go field, because the wire is the
// subject and the two differ where it matters: the filter types used to send
// "Include", capitalised, carrying no tag at all.
//
// Every entry says why the key is on the wire. The list opened with 53 marked
// "grandfathered" -- true, but not decided -- and bomly-sdk#78 spent them:
// eleven fields took omitempty and left this list, which is eleven keys these
// rules begin guarding. The rest are below in four groups, each group the
// reason its keys are always sent. The grandfather clause is gone; an entry
// added here from now on is a claim someone made.
//
// The eleven that left were checked against bomly-cli and the plugin repos
// first, because omitting a key relaxes the schema: none is read by key
// presence, none appears in a published schema or a golden, and absence
// decodes to the same value as the null they used to send. The ones that
// stayed include two the check kept here -- epss, which bomly-cli's smoke
// harness uses to recognise a vulnerability object by key presence, and
// affected_dependency_refs, which its published schema marks required.
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
	"nodeWire.id":                          "the encoded form of that same identity",
	"DependencyEdge.fromId":                "an edge without both endpoints joins nothing",
	"DependencyEdge.toId":                  "an edge without both endpoints joins nothing",
	"DependencyNode.kind":                  "the sealed union's discriminator (ADR-0041)",
	"DetectorWarning.type":                 "the discriminator policy branches on: DegradesCoverage reads it",
	"DetectorWarning.message":              "a warning with no message is nothing a reader can act on",
	"PackageRemediation.status":            "the discriminator that says how far the fix evidence goes",
	"PackageRemediationSuggestion.action":  "the discriminator that says which remediation is suggested",
	"PackageRemediationSuggestion.affected_dependency_refs": "the occurrences the suggestion applies to; " +
		"one that names none cannot be applied, and bomly-cli publishes the key as required",
	"RemediationStrategyHint.action": "the discriminator that says which strategy the hint is evidence for",
	"Reachability.status":            "the discriminator the annotation exists to carry",
	"ReachabilityEvidence.status":    "the discriminator the finding exists to carry",
	"RemediationHint.dependencyRef":  "a hint that does not name its occurrence cannot be applied",
	"ResolutionFallback.from":        "the failed primary detector this record exists to name",

	// Booleans whose whole purpose is the false answer.
	"ReadyResponse.ready":           "false is the answer this response exists to give",
	"ApplicableResponse.applicable": "false is the answer this response exists to give",
	"ResolutionMetadata.install_executed": "false is the common answer and the one a CI reader needs: " +
		"no install ran, so the graph came from committed files",
	"DependencyDetailTransition.beforeRegistryEligible": "a registry-eligibility change is the pair; " +
		"the false side is the change being reported, and absent would read as unstated",
	"DependencyDetailTransition.afterRegistryEligible": "a registry-eligibility change is the pair; " +
		"the false side is the change being reported, and absent would read as unstated",

	// Scores, where zero is a measurement. Absence of data is the absence of
	// the containing record, not a missing key inside it.
	"EPSSScore.epss":                  "0.0 is a probability; no EPSS data means no EPSSScore at all",
	"PackageScorecard.aggregateScore": "0.0 is a score; unscored is -1, and no run means no PackageScorecard",
	"PackageScorecardCheck.score":     "0 is a score; inconclusive is -1",
	"RiskScore.score":                 "0 is a score -- no risk found -- not a missing one",

	// Struct-valued fields. encoding/json never omits a struct, so omitempty
	// on one changes no bytes and no tag can take these keys off the wire --
	// which is also why three of them already carry a marker that does
	// nothing. Only a pointer or omitzero would omit them, and either is a
	// wire change of its own rather than the marker this list is about. Each
	// reason below says why the value is meant to be there as well.
	"MatchRequest.executionTarget":        "the target the host is scanning, set on every request",
	"MatchRequest.subprojectInfo":         "the subproject the request is scoped to",
	"MatchRequest.query":                  "an empty query is the whole-scope query, not a missing one",
	"MatchRequest.matcherFilter":          "an empty filter is 'narrow nothing', which is a filter",
	"AnalyzeRequest.executionTarget":      "the target the host is scanning, set on every request",
	"AnalyzeRequest.subprojectInfo":       "the subproject the request is scoped to",
	"AnalyzeRequest.query":                "an empty query is the whole-scope query, not a missing one",
	"AnalyzeRequest.analyzerFilter":       "an empty filter is 'narrow nothing', which is a filter",
	"AuditRequest.executionTarget":        "the target the host is scanning, set on every request",
	"AuditRequest.subprojectInfo":         "the subproject the request is scoped to",
	"AuditRequest.query":                  "an empty query is the whole-scope query, not a missing one",
	"AuditRequest.auditorFilter":          "an empty filter is 'narrow nothing', which is a filter",
	"DetectionRequest.executionTarget":    "the target the host is scanning, set on every request",
	"DetectionRequest.subproject":         "the subproject the request is scoped to",
	"DetectionRequest.query":              "an empty query is the whole-scope query, not a missing one",
	"DetectionRequest.detectorFilter":     "an empty filter is 'narrow nothing', which is a filter",
	"DetectionResult.subprojectInfo":      "the subproject the returned graphs belong to",
	"DetectionResult.rootExecutionTarget": "the target the detection ran against",
	"Subproject.executionTarget":          "where the subproject was found",
	"CallPath.sink":                       "the symbol the path leads to, which is what makes it a path",
	"GraphEntry.manifest":                 "the manifest this graph is scoped to",
	"RemediationHintRequest.detection":    "the completed detection the hint request is about",
	"CallFrame.position":                  "declares omitempty; encoding/json ignores it on a struct value",
	"MatchResult.matcherStats":            "declares omitempty; encoding/json ignores it on a struct value",
	"PackageScorecard.runDate":            "declares omitempty; encoding/json ignores it on a time.Time",
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
	"nodeWire.id":                                           "the encoded node identity",
	"DependencyEdge.fromId":                                 "an edge without both endpoints joins nothing",
	"DependencyEdge.toId":                                   "an edge without both endpoints joins nothing",
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
			if reason, required := intentionallyRequired[key]; required {
				// Checked, not skipped. An exemption says this field
				// carries no marker on purpose; if one appears, the
				// exemption and the tag now claim opposite things and the
				// bytes cannot tell them apart, because encoding/json emits
				// a zero struct either way. Silence here would let the
				// marker be added -- or swapped for omitzero, which looks
				// like a marker and is not this one -- with both wire
				// guards still green.
				if hasJSONOption(options, "omitempty") {
					t.Errorf("%s is listed as required (%s) and yet declares omitempty; the list and "+
						"the tag disagree, so one of them is wrong", key, reason)
				}
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
