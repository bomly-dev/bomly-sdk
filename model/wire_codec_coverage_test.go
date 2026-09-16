package model

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// The structs Graph's custom codec emits are unexported, so the contract
// package's wire walk (its reachableWireTypes follows exported fields only)
// cannot register them as roots. This package can name them, so it applies
// the same two rules here: a zero value puts only declared always-sent keys
// on the wire, and every tagged field declares omitempty unless it is one of
// those keys.
func TestWireCodecStructsDeclareOmitEmpty(t *testing.T) {
	alwaysSent := map[string]string{
		"nodeWire.id": "the encoded node identity (ADR-0041)",
	}
	for _, root := range []any{graphJSON{}, nodeWire{}} {
		typ := reflect.TypeOf(root)
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
				t.Errorf("a zero %s puts %q on the wire; give the field omitempty or declare it always sent", typ.Name(), key)
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
			if !hasOmitEmpty(options) {
				t.Errorf("%s.%s is on the wire without omitempty", typ.Name(), field.Name)
			}
		}
	}
}

// hasOmitEmpty reports whether a json tag's option list names omitempty
// exactly (not as a prefix of a longer option).
func hasOmitEmpty(options string) bool {
	for option := range strings.SplitSeq(options, ",") {
		if option == "omitempty" {
			return true
		}
	}
	return false
}
