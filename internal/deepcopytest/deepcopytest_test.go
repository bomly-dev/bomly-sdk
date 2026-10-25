package deepcopytest

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type inner struct {
	Values []string
}

type sample struct {
	Name    string
	Pointer *inner
	Slice   []inner
	Map     map[string]any
	Any     any
	private map[string]int
}

func copyAny(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for k, nested := range typed {
			out[k] = copyAny(nested)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, nested := range typed {
			out[i] = copyAny(nested)
		}
		return out
	default:
		return v
	}
}

func deepCopy(s sample) sample {
	out := s
	out.Pointer = &inner{Values: slices.Clone(s.Pointer.Values)}
	out.Slice = make([]inner, len(s.Slice))
	for i, v := range s.Slice {
		out.Slice[i] = inner{Values: slices.Clone(v.Values)}
	}
	out.Map = copyAny(s.Map).(map[string]any)
	out.Any = copyAny(s.Any)
	out.private = maps.Clone(s.private)
	return out
}

// TestAliasesReportsEveryKindOfSharing is the checker's own proof that it
// can fail: a shallow copy must be reported at every shared pointer, map,
// slice and unexported field, and a deep copy at none.
func TestAliasesReportsEveryKindOfSharing(t *testing.T) {
	var source sample
	Fill(&source)
	source.private = map[string]int{"k": 1}
	if source.Pointer == nil || len(source.Slice) != 2 || len(source.Map) != 2 || source.Any == nil {
		t.Fatalf("Fill left a field empty: %+v", source)
	}

	shallow := source
	got := Aliases(&source, &shallow)
	for _, want := range []string{"$.Pointer: shared pointer", "$.Slice: shared slice backing array", "$.Map: shared map", "$.private: shared map"} {
		if !slices.Contains(got, want) {
			t.Errorf("shallow copy: missing %q in %v", want, got)
		}
	}

	nested := deepCopy(source)
	nested.Pointer.Values = source.Pointer.Values
	if got := Aliases(&source, &nested); !slices.Equal(got, []string{"$.Pointer.Values: shared slice backing array"}) {
		t.Errorf("nested alias: got %v", got)
	}

	deep := deepCopy(source)
	if got := Aliases(&source, &deep); len(got) != 0 {
		t.Errorf("deep copy reported aliases: %v", got)
	}
}

// TestDeepcopytestIsImportedOnlyByTests keeps the reflective checker out of
// production code: the Clone methods it verifies are hand-written so the hot
// path never pays for reflection, and a production import would reintroduce
// exactly that.
func TestDeepcopytestIsImportedOnlyByTests(t *testing.T) {
	const importPath = `"github.com/bomly-dev/bomly-sdk/internal/deepcopytest"`
	root := filepath.Join("..", "..")
	var offenders []string
	scanned := 0
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if name := info.Name(); strings.HasPrefix(name, ".") && name != "." && name != ".." {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		if strings.Contains(string(source), importPath) {
			offenders = append(offenders, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if scanned == 0 {
		t.Fatalf("no Go files found under %s; the guard scanned nothing", root)
	}
	if len(offenders) > 0 {
		t.Fatalf("non-test code imports internal/deepcopytest: %v", offenders)
	}
}
