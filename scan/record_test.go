package scan

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk/model"
)

// The contract package's wire walk stops at the model and plugin packages,
// so a record's own structs are guarded here with the same two rules: a
// zero value puts only declared always-sent keys on the wire, and every
// tagged field declares omitempty or omitzero unless it is one of those
// keys. Every struct reachable from Record inside this package is walked.
func TestRecordFieldsDeclareOmitEmpty(t *testing.T) {
	alwaysSent := recordAlwaysSent
	pkgPath := reflect.TypeOf(Record{}).PkgPath()
	seen := map[reflect.Type]bool{}
	var types []reflect.Type
	var walk func(reflect.Type)
	walk = func(typ reflect.Type) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array || typ.Kind() == reflect.Map {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || typ.PkgPath() != pkgPath || seen[typ] {
			return
		}
		seen[typ] = true
		types = append(types, typ)
		for i := range typ.NumField() {
			walk(typ.Field(i).Type)
		}
	}
	walk(reflect.TypeOf(Record{}))
	if len(types) < 10 {
		t.Fatalf("walked only %d types; the walk is broken", len(types))
	}
	for _, typ := range types {
		encoded, err := json.Marshal(reflect.New(typ).Interface())
		if err != nil {
			t.Fatalf("marshal zero %s: %v", typ.Name(), err)
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &object); err != nil {
			t.Fatalf("zero %s is not a JSON object: %v", typ.Name(), err)
		}
		for key := range object {
			if _, declared := alwaysSent[typ.Name()+"."+key]; !declared {
				t.Errorf("a zero %s puts %q on the wire; give the field omitempty or omitzero, or declare it always sent", typ.Name(), key)
			}
		}
		for i := range typ.NumField() {
			field := typ.Field(i)
			tag, ok := field.Tag.Lookup("json")
			if !ok || strings.HasPrefix(tag, "-") {
				continue
			}
			name, options, _ := strings.Cut(tag, ",")
			if _, required := alwaysSent[typ.Name()+"."+name]; required {
				// An always-sent key that also carries an omit option would be
				// dropped when empty, which is what the declaration denies.
				if hasOmitOption(options) {
					t.Errorf("%s.%s is declared always sent but carries an omit option", typ.Name(), field.Name)
				}
				continue
			}
			if !hasOmitOption(options) {
				t.Errorf("%s.%s is on the wire without omitempty or omitzero", typ.Name(), field.Name)
			}
			if name != strings.ToLower(name) {
				t.Errorf("%s.%s: key %q is not snake_case", typ.Name(), field.Name, name)
			}
		}
	}
}

// recordAlwaysSent are the keys a zero value of a record type still writes,
// by "Type.key": the schema version, and the IteratedCollections the record
// types own. TestIteratedCollectionsMatchTheGuard derives
// IteratedCollections from this map and from packageWire, so the two
// cannot drift.
var recordAlwaysSent = map[string]string{
	"Record.schema_version": "the one key every record carries",
	"Record.manifests":      "iterated collection",
	"Record.packages":       "iterated collection",
	"Record.findings":       "iterated collection",
	"Record.warnings":       "iterated collection",
	"Record.waivers":        "iterated collection",
	"Manifest.dependencies": "iterated collection",
	"Dependency.depends_on": "iterated collection",
	"Dependency.licenses":   "iterated collection",
}

func hasOmitOption(options string) bool {
	for option := range strings.SplitSeq(options, ",") {
		if option == "omitempty" || option == "omitzero" {
			return true
		}
	}
	return false
}

// TestSubjectCannotCarryALocalPath pins the one thing Subject must not hold.
func TestSubjectCannotCarryALocalPath(t *testing.T) {
	typ := reflect.TypeOf(Subject{})
	for i := range typ.NumField() {
		name := strings.ToLower(typ.Field(i).Name)
		if strings.Contains(name, "location") || strings.Contains(name, "path") || strings.Contains(name, "dir") {
			t.Fatalf("Subject.%s would carry a local path", typ.Field(i).Name)
		}
	}
}

// The subject applies the commit gate in its codec, the same one the
// execution target applies, so a record cannot carry a ref name or a
// padded hash as a commit on either direction.
func TestSubjectCodecAppliesTheCommitGate(t *testing.T) {
	var subject Subject
	if err := json.Unmarshal([]byte(`{"kind":"git-repository","commit_sha":" 0123ABCDEF0123abcdef ","image_reference":" alpine:3.20 "}`), &subject); err != nil {
		t.Fatal(err)
	}
	if subject.CommitSHA != "0123abcdef0123abcdef" || subject.ImageReference != "alpine:3.20" {
		t.Fatalf("decoded subject = %+v", subject)
	}
	data, err := json.Marshal(Subject{Kind: "git-repository", Ref: "main", CommitSHA: "main"})
	if err != nil || string(data) != `{"kind":"git-repository","ref":"main"}` {
		t.Fatalf("encoded %s, %v; want the non-commit cleared", data, err)
	}
}

// A dependency's relationship is a closed vocabulary; the codec gates it on
// both directions so a comparison never takes " DIRECT " or an unknown word
// as a stated relationship.
func TestDependencyCodecGatesTheRelationship(t *testing.T) {
	var decoded Dependency
	if err := json.Unmarshal([]byte(`{"id":"pkg:npm/a@1.0.0","relationship":" DIRECT "}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Relationship != model.DependencyRelationshipDirect {
		t.Fatalf("decoded relationship = %q, want direct", decoded.Relationship)
	}
	existing := Dependency{ID: "pkg:npm/a@1.0.0", Name: "a", Relationship: model.DependencyRelationshipTransitive}
	if err := json.Unmarshal([]byte(`{"relationship":"direct"}`), &existing); err != nil {
		t.Fatal(err)
	}
	if existing.Name != "a" || existing.Relationship != model.DependencyRelationshipDirect {
		t.Fatalf("a partial object did not merge into the existing dependency: %+v", existing)
	}
	data, err := json.Marshal(Dependency{ID: "pkg:npm/a@1.0.0", Relationship: "sideways"})
	if err != nil || string(data) != `{"id":"pkg:npm/a@1.0.0","depends_on":[],"licenses":[]}` {
		t.Fatalf("encoded %s, %v; want the unknown relationship cleared", data, err)
	}
}

// Every iterated collection is present, as [], in a record that found
// nothing: a consumer's `.findings[]` or `.depends_on[]` never meets a
// missing key.
func TestRecordWritesIteratedCollectionsWhenEmpty(t *testing.T) {
	data, err := Encode(&Record{Manifests: []Manifest{{Path: "go.mod", Dependencies: []Dependency{{ID: "pkg:golang/example.test/a@v1.0.0"}}}},
		Packages: []*model.Package{{Coordinates: model.Coordinates{PURL: "pkg:golang/example.test/a@v1.0.0"}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"findings":[]`, `"warnings":[]`, `"waivers":[]`, `"depends_on":[]`, `"licenses":[]`, `"vulnerabilities":[]`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("%s missing from %s", want, data)
		}
	}
	empty, err := Encode(&Record{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"manifests":[]`, `"packages":[]`, `"findings":[]`} {
		if !strings.Contains(string(empty), want) {
			t.Fatalf("%s missing from an empty record: %s", want, empty)
		}
	}
	if _, err := Decode(data); err != nil {
		t.Fatalf("a record with empty collections did not verify: %v", err)
	}
	// Marshaling a record directly, not through Encode, takes the same shape.
	direct, err := json.Marshal(Record{SchemaVersion: SchemaVersion})
	if err != nil || !strings.Contains(string(direct), `"findings":[]`) {
		t.Fatalf("direct marshal = %s, %v", direct, err)
	}
}

// A record written before the collections were always present omitted an
// empty one, and digested its absence as null; it still decodes and
// verifies.
func TestDecodeReadsARecordThatOmittedEmptyCollections(t *testing.T) {
	null := digestOf([]byte("null"))
	old := `{"schema_version":"bomly.scan.v1","command":"scan","digests":{"manifests":"` + null + `","packages":"` + null + `","findings":"` + null + `"}}`
	r, err := Decode([]byte(old))
	if err != nil {
		t.Fatalf("an older record was refused: %v", err)
	}
	if len(r.Findings) != 0 || len(r.Manifests) != 0 {
		t.Fatalf("decoded %+v", r)
	}
}

// A document's package carries the same keys as the SDK package plus its
// two iterated collections, and encoding never edits the holder's package.
func TestPackageWritesItsIteratedCollections(t *testing.T) {
	held := &model.Package{Coordinates: model.Coordinates{PURL: "pkg:npm/a@1.0.0", Name: "a"},
		Vulnerabilities: []model.Vulnerability{{ID: "CVE-2", Source: "osv"}, {ID: "CVE-1", Source: "osv"}}}
	data, err := json.Marshal(Package{held})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"licenses":[]`) || !strings.Contains(string(data), `"purl":"pkg:npm/a@1.0.0"`) {
		t.Fatalf("package = %s", data)
	}
	if held.Vulnerabilities[0].ID != "CVE-2" {
		t.Fatal("encoding reordered the holder's vulnerabilities")
	}
	var plain, wrapped map[string]json.RawMessage
	sdk, _ := json.Marshal(held)
	if err := json.Unmarshal(sdk, &plain); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &wrapped); err != nil {
		t.Fatal(err)
	}
	for key, value := range plain {
		if string(wrapped[key]) != string(value) {
			t.Fatalf("key %q differs: %s vs %s", key, wrapped[key], value)
		}
	}
	if b, _ := json.Marshal(Package{}); string(b) != "null" {
		t.Fatalf("a nil package encoded as %s", b)
	}
}

// recordWire must list Record's fields, in order, with the same keys; only
// the packages element type differs.
func TestRecordWireMirrorsRecord(t *testing.T) {
	record, wire := reflect.TypeOf(Record{}), reflect.TypeOf(recordWire{})
	if record.NumField() != wire.NumField() {
		t.Fatalf("Record has %d fields, recordWire %d", record.NumField(), wire.NumField())
	}
	for i := range record.NumField() {
		a, b := record.Field(i), wire.Field(i)
		if a.Name != b.Name || a.Tag != b.Tag {
			t.Fatalf("field %d: Record.%s %q, recordWire.%s %q", i, a.Name, a.Tag, b.Name, b.Tag)
		}
		if a.Name != "Packages" && a.Type != b.Type {
			t.Fatalf("field %s: type %v vs %v", a.Name, a.Type, b.Type)
		}
	}
}

// IteratedCollections is exactly what the guard accepts as always sent,
// plus the package collections packageWire writes without an omit option:
// derived from the declarations, not from a second hand-written list.
func TestIteratedCollectionsMatchTheGuard(t *testing.T) {
	prefixes := map[string]string{"Record": "", "Manifest": "manifests[].", "Dependency": "manifests[].dependencies[]."}
	derived := map[string]bool{}
	for key := range recordAlwaysSent {
		typeName, field, _ := strings.Cut(key, ".")
		if key == "Record.schema_version" {
			continue
		}
		prefix, ok := prefixes[typeName]
		if !ok {
			t.Fatalf("always-sent key %q belongs to a type with no path in the record", key)
		}
		derived[prefix+field] = true
	}
	wire := reflect.TypeOf(packageWire{})
	for i := range wire.NumField() {
		field := wire.Field(i)
		if field.Anonymous {
			continue
		}
		name, options, _ := strings.Cut(field.Tag.Get("json"), ",")
		if hasOmitOption(options) {
			t.Errorf("packageWire.%s is an iterated collection but carries an omit option", field.Name)
		}
		derived["packages[]."+name] = true
	}
	listed := map[string]bool{}
	for _, path := range IteratedCollections {
		listed[path] = true
	}
	if !reflect.DeepEqual(derived, listed) {
		t.Fatalf("IteratedCollections = %v, but the declarations derive %v", IteratedCollections, derived)
	}
}

// Decoding into a zero Package, standalone or in a slice, must not panic on
// the embedded nil pointer, and must read through model.Package's codec.
func TestPackageDecodesIntoAZeroValue(t *testing.T) {
	var one Package
	if err := json.Unmarshal([]byte(`{"purl":"pkg:npm/a@1.0.0","name":"a","licenses":[],"vulnerabilities":[]}`), &one); err != nil {
		t.Fatal(err)
	}
	if one.Package == nil || one.PURL != "pkg:npm/a@1.0.0" {
		t.Fatalf("decoded %+v", one.Package)
	}
	var many []Package
	if err := json.Unmarshal([]byte(`[{"purl":"pkg:npm/b@1.0.0"},null]`), &many); err != nil {
		t.Fatal(err)
	}
	if len(many) != 2 || many[0].Package == nil || many[1].Package != nil {
		t.Fatalf("decoded %+v", many)
	}
	data, err := json.Marshal(many[0])
	if err != nil {
		t.Fatal(err)
	}
	var again Package
	if err := json.Unmarshal(data, &again); err != nil || again.PURL != "pkg:npm/b@1.0.0" {
		t.Fatalf("round trip = %+v, %v", again.Package, err)
	}
}
