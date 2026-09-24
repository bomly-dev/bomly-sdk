package scan

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// The contract package's wire walk stops at the model and plugin packages,
// so a record's own structs are guarded here with the same two rules: a
// zero value puts only declared always-sent keys on the wire, and every
// tagged field declares omitempty or omitzero unless it is one of those
// keys. Every struct reachable from Record inside this package is walked.
func TestRecordFieldsDeclareOmitEmpty(t *testing.T) {
	alwaysSent := map[string]string{
		"Record.schema_version": "the one key every record carries",
	}
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
				continue
			}
			if !hasOmitOption(options) {
				t.Errorf("%s.%s is on the wire without omitempty or omitzero", typ.Name(), field.Name)
			}
			if strings.Contains(name, "A") || strings.Contains(name, "B") || strings.Contains(name, "C") {
				t.Errorf("%s.%s: key %q is not snake_case", typ.Name(), field.Name, name)
			}
		}
	}
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
