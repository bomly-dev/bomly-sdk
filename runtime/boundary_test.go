package runtime

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestNothingHereIsAWirePayload fails when a struct in this package carries a
// json tag. Every bomly.plugin.v1 payload lives in the root package, where
// the omitempty coverage walk (wire_omitempty_coverage_test.go) reaches it by
// following exported fields from the root's wire roots; that walk stops at
// the root's package path, so a payload type declared here would escape it
// silently. This package adapts and transports payloads; it declares none.
func TestNothingHereIsAWirePayload(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			field, ok := n.(*ast.Field)
			if !ok || field.Tag == nil {
				return true
			}
			if strings.Contains(field.Tag.Value, `json:"`) {
				t.Errorf("%s declares a json-tagged field; wire payloads belong in the root package, "+
					"where TestWireV1TaggedFieldsDeclareOmitEmpty can see them", fset.Position(field.Pos()))
			}
			return true
		})
	}
}
