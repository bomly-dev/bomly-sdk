package sdk

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// packageurl-go decides what casing a package URL's version canonicalizes to,
// per type, inside Normalize -- which every identity this module mints runs
// through. NormalizeCoordinates must not contradict it.
//
// Referencing the library would make a *rename* a compile error and do
// nothing about an *addition*, which is the way this kind of table goes
// wrong: correct the day it is written, quietly lossy the day the
// specification grows. So this reads the library's own source and fails when
// the set of version-lowercasing types changes.
//
// If it fails: check whether the new type needs handling here, then update
// wantLowercasingTypes with the reason.
func TestVersionCasingMatchesPackageURLLibrary(t *testing.T) {
	// The types packageurl-go lowercases the version for, as of v0.1.7.
	// huggingface only: the purl specification says a version is otherwise
	// case sensitive.
	wantLowercasingTypes := map[string]struct{}{"TypeHuggingface": {}}

	got := versionLoweringTypes(t)
	for name := range got {
		if _, expected := wantLowercasingTypes[name]; !expected {
			t.Errorf("packageurl-go now lowercases versions for %s; decide whether NormalizeCoordinates must follow, then update wantLowercasingTypes", name)
		}
	}
	for name := range wantLowercasingTypes {
		if _, still := got[name]; !still {
			t.Errorf("packageurl-go no longer lowercases versions for %s; update wantLowercasingTypes", name)
		}
	}
}

// A Maven snapshot keeps the spelling the manifest used. This is the defect
// the blanket lowercasing caused: the coordinates, and so every SBOM built
// from them, published a version Maven does not resolve.
func TestVersionCasingIsPreservedForCaseSensitiveEcosystems(t *testing.T) {
	for _, tc := range []struct {
		name   string
		coords Coordinates
		want   string
	}{
		{
			name:   "maven snapshot",
			coords: Coordinates{Ecosystem: EcosystemMaven, Org: "com.acme", Name: "app", Version: "1.0-SNAPSHOT"},
			want:   "1.0-SNAPSHOT",
		},
		{
			name:   "go pseudo-version keeps its case",
			coords: Coordinates{Ecosystem: EcosystemGo, Name: "example.com/mod", Version: "v0.0.0-20260101000000-AbCdEf123456"},
			want:   "v0.0.0-20260101000000-AbCdEf123456",
		},
		{
			name:   "nuget prerelease tag",
			coords: Coordinates{Ecosystem: EcosystemDotNet, Name: "Newtonsoft.Json", Version: "13.0.1-Beta2"},
			want:   "13.0.1-Beta2",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			coords := tc.coords
			NormalizeCoordinates(&coords)
			if coords.Version != tc.want {
				t.Fatalf("normalized version = %q, want %q", coords.Version, tc.want)
			}
			node, err := NewDependencyNode(tc.coords)
			if err != nil {
				t.Fatalf("NewDependencyNode() error = %v", err)
			}
			if node.Version != tc.want {
				t.Fatalf("node version = %q, want %q", node.Version, tc.want)
			}
			if !strings.HasSuffix(node.NodeID(), "@"+tc.want) {
				t.Fatalf("node ID = %q, want it to end in @%s", node.NodeID(), tc.want)
			}
		})
	}
}

// versionLoweringTypes parses packageurl-go's typeAdjustVersion and returns
// the type constants it lowercases.
func versionLoweringTypes(t *testing.T) map[string]struct{} {
	t.Helper()

	source := filepath.Join(packageURLModuleDir(t), "packageurl.go")
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, source, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", source, err)
	}

	found := map[string]struct{}{}
	ast.Inspect(parsed, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "typeAdjustVersion" {
			return true
		}
		ast.Inspect(fn, func(inner ast.Node) bool {
			clause, ok := inner.(*ast.CaseClause)
			if !ok || !clauseLowercases(clause) {
				return true
			}
			for _, expr := range clause.List {
				if ident, ok := expr.(*ast.Ident); ok {
					found[ident.Name] = struct{}{}
				}
			}
			return true
		})
		return false
	})
	if len(found) == 0 {
		t.Fatal("found no version-lowercasing types in packageurl-go; the function shape changed, so this test is no longer reading it")
	}
	return found
}

func clauseLowercases(clause *ast.CaseClause) bool {
	lowered := false
	ast.Inspect(clause, func(n ast.Node) bool {
		selector, ok := n.(*ast.SelectorExpr)
		if ok && selector.Sel.Name == "ToLower" {
			lowered = true
		}
		return !lowered
	})
	return lowered
}

// packageURLModuleDir locates the pinned packageurl-go source in the module
// cache, so the test reads the version this module actually compiles against.
func packageURLModuleDir(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "go", "list", "-m", "-f", "{{.Dir}}", "github.com/package-url/packageurl-go").Output()
	if err != nil {
		t.Skipf("packageurl-go source is unavailable (module cache not populated): %v", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		t.Skip("packageurl-go module directory is empty")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("packageurl-go module directory is unreadable: %v", err)
	}
	return dir
}

// The two normalization paths must agree. NewDependencyNode projects its
// coordinates from the minted identity, so it follows whatever casing the
// library applies; a direct NormalizeCoordinates call has to reach the same
// answer, or the same package normalizes differently depending on which entry
// point a caller used.
//
// Hugging Face is the one type where that is observable today, because it is
// the only one packageurl-go folds -- which is exactly why the rule is read
// off the canonical package URL rather than transcribed here.
func TestNormalizeCoordinatesAgreesWithTheConstructor(t *testing.T) {
	for _, tc := range []struct {
		name   string
		coords Coordinates
		want   string
	}{
		{
			name:   "hugging face folds, because the library folds it",
			coords: Coordinates{PURL: "pkg:huggingface/microsoft/bert@V1-Beta"},
			want:   "v1-beta",
		},
		{
			name:   "maven does not",
			coords: Coordinates{Ecosystem: EcosystemMaven, Org: "com.acme", Name: "app", Version: "1.0-SNAPSHOT"},
			want:   "1.0-SNAPSHOT",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			normalized := tc.coords
			NormalizeCoordinates(&normalized)
			if normalized.Version != tc.want {
				t.Errorf("NormalizeCoordinates version = %q, want %q", normalized.Version, tc.want)
			}

			node, err := NewDependencyNode(tc.coords)
			if err != nil {
				t.Fatalf("NewDependencyNode() error = %v", err)
			}
			if node.Version != tc.want {
				t.Errorf("constructed version = %q, want %q", node.Version, tc.want)
			}
			if node.Version != normalized.Version {
				t.Errorf("the two normalization paths disagree: %q vs %q", normalized.Version, node.Version)
			}
		})
	}
}
