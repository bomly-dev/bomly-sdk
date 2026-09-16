package model

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNormalizePackageIdentityPython(t *testing.T) {
	coords := Coordinates{Ecosystem: EcosystemPython, Name: " Requests_Toolbelt ", Version: "1.0.0RC1"}

	// NormalizeDependencyIdentity is gone: NormalizeCoordinates returns the
	// applied rules, and the constructors record the provenance breadcrumbs.
	applied := NormalizeCoordinates(&coords)
	if !reflect.DeepEqual(applied, []string{"name", "version"}) {
		t.Fatalf("NormalizeCoordinates() applied = %#v", applied)
	}

	pkg := mustDep(t, Coordinates{Ecosystem: EcosystemPython, Name: " Requests_Toolbelt ", Version: "1.0.0RC1"})
	if pkg.Name != "requests-toolbelt" {
		normReturnNameMismatch(t, pkg.Name, "requests-toolbelt")
	}
	// The version takes its PEP 440 canonical form: PyPI holds "1.0.0RC1"
	// and "1.0.0rc1" as one release, so the identity does too. The fold is
	// pypi's alone -- see TestPyPIVersionFoldsToOneIdentity -- and the
	// spelling the manifest used survives in the provenance breadcrumb.
	if pkg.Version != "1.0.0rc1" {
		normReturnNameMismatch(t, pkg.Version, "1.0.0rc1")
	}
	normAssertAppliedMetadata(t, pkg.Metadata, []string{"name", "version"})
	if got := pkg.Metadata[normMetadataOriginalVersionKey]; got != "1.0.0RC1" {
		t.Fatalf("original version breadcrumb = %v, want the manifest's spelling", got)
	}
}

func TestNormalizePackageIdentityRust(t *testing.T) {
	pkg := mustDep(t, Coordinates{PackageManager: PackageManagerCargo, Name: "Serde_JSON", Version: "1.0.0-RC1"})

	if pkg.Name != "serde-json" {
		normReturnNameMismatch(t, pkg.Name, "serde-json")
	}
	if pkg.Version != "1.0.0-RC1" {
		normReturnNameMismatch(t, pkg.Version, "1.0.0-RC1")
	}
	normAssertAppliedMetadata(t, pkg.Metadata, []string{"name"})
}

func TestNormalizePackageIdentityNPMScopedName(t *testing.T) {
	pkg := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "@Types/Node", Version: "20.11.30"})

	if pkg.Org != "types" {
		normReturnNameMismatch(t, pkg.Org, "types")
	}
	if pkg.Name != "node" {
		normReturnNameMismatch(t, pkg.Name, "node")
	}
	normAssertAppliedMetadata(t, pkg.Metadata, []string{"npm-scope", "org", "name"})
}

func TestNormalizePackageIdentityGoPath(t *testing.T) {
	pkg := mustDep(t, Coordinates{Ecosystem: EcosystemGo, Name: "github.com\\Example\\lib//v2", Version: "V2.1.0-RC1"})

	// The identity splits a Go module path at its trailing segment, so the
	// module path is read back through the ecosystem-native accessor rather
	// than the bare Name field (ADR-0021). The path is lowercased because the
	// purl specification's golang type says so and the library applies that
	// rule -- identity delegates type semantics rather than keeping a second
	// opinion (ADR-0041).
	if got := pkg.EcosystemName(); got != "github.com/example/lib/v2" {
		normReturnNameMismatch(t, got, "github.com/example/lib/v2")
	}
	// The version is not: the same library leaves a golang version verbatim,
	// and so does this.
	if pkg.Version != "V2.1.0-RC1" {
		normReturnNameMismatch(t, pkg.Version, "V2.1.0-RC1")
	}
	normAssertAppliedMetadata(t, pkg.Metadata, []string{"name"})
}

func TestNormalizePackageIdentityUsesCanonicalEcosystemAliases(t *testing.T) {
	tests := []struct {
		name    string
		manager PackageManager
		input   string
		want    string
	}{
		{name: "bun uses npm rules", manager: PackageManagerBun, input: "PACKage", want: "package"},
		{name: "pdm uses python rules", manager: PackageManagerPDM, input: "Requests_Toolbelt", want: "requests-toolbelt"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkg := mustDep(t, Coordinates{PackageManager: tc.manager, Name: tc.input})

			if pkg.Name != tc.want {
				normReturnNameMismatch(t, pkg.Name, tc.want)
			}
		})
	}
}

func normAssertAppliedMetadata(t *testing.T, metadata map[string]any, want []string) {
	t.Helper()
	if metadata == nil {
		t.Fatal("expected metadata to be recorded")
	}
	got, ok := metadata[normMetadataAppliedKey].([]string)
	if !ok {
		t.Fatalf("expected %q metadata to be []string, got %#v", normMetadataAppliedKey, metadata[normMetadataAppliedKey])
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected normalization metadata %#v, got %#v", want, got)
	}
}

func normReturnNameMismatch(t *testing.T, got, want string) {
	t.Helper()
	t.Fatalf("expected %q, got %q", want, got)
}

// PyPI holds "1.0.0RC1" and "1.0.0rc1" as one release: PEP 440 normalizes
// case and the pre-release spellings, and the index refuses to hold both. Two
// identities for the pair were two components for one package -- two matching
// results, duplicate vulnerabilities -- which is the duplicate-identity
// problem ADR-0041 exists to remove. v0.9.0 dropped the blanket lowercasing
// that folded this by accident (and corrupted Maven's 1.0-SNAPSHOT); this is
// the rule that replaces it, scoped to pypi and delegated to the library
// that owns the grammar.
func TestPyPIVersionFoldsToOneIdentity(t *testing.T) {
	upper := mustDep(t, Coordinates{Ecosystem: EcosystemPython, Name: "requests-toolbelt", Version: "1.0.0RC1"})
	lower := mustDep(t, Coordinates{Ecosystem: EcosystemPython, Name: "requests-toolbelt", Version: "1.0.0rc1"})
	if upper.NodeID() != lower.NodeID() {
		t.Fatalf("two identities for one PyPI release: %q and %q", upper.NodeID(), lower.NodeID())
	}
	if upper.NodeID() != "pkg:pypi/requests-toolbelt@1.0.0rc1" {
		t.Fatalf("identity = %q, want the PEP 440 canonical version", upper.NodeID())
	}

	// The coordinates say what the identity says -- the normalized version
	// replaces the stated one, as every other projection does -- and the
	// manifest's spelling survives in the provenance breadcrumb, so a reader
	// can still see what was written.
	if upper.Version != "1.0.0rc1" {
		t.Fatalf("Version = %q, want it projected from the identity", upper.Version)
	}
	if got := upper.Metadata[normMetadataOriginalVersionKey]; got != "1.0.0RC1" {
		t.Fatalf("original version breadcrumb = %v, want %q", got, "1.0.0RC1")
	}

	// Every path to an identity folds the same way: a stated package URL on
	// the coordinates, a raw package URL, and any Python package-manager
	// token, since they all mint the pypi type.
	for name, node := range map[string]*DependencyNode{
		"stated purl": mustDep(t, Coordinates{PURL: "pkg:pypi/requests-toolbelt@1.0.0RC1"}),
		"raw purl":    mustDepPURL(t, "pkg:pypi/Requests_Toolbelt@1.0.0.RC.1"),
		"poetry":      mustDep(t, Coordinates{PackageManager: PackageManagerPoetry, Name: "requests-toolbelt", Version: "1.0.0-rc1"}),
	} {
		if node.NodeID() != upper.NodeID() {
			t.Errorf("%s: identity = %q, want %q", name, node.NodeID(), upper.NodeID())
		}
	}

	// A version PEP 440 does not describe is left as written, and the
	// package is still constructed: an unconventional version is not a
	// reason to drop something that is installed.
	dated := mustDep(t, Coordinates{Ecosystem: EcosystemPython, Name: "internal", Version: "2021-03-01"})
	if dated.Version != "2021-03-01" || dated.NodeID() != "pkg:pypi/internal@2021-03-01" {
		t.Fatalf("unparseable version: Version = %q, id = %q; want both as written", dated.Version, dated.NodeID())
	}

	// The rule is pypi's alone. Maven versions are case sensitive, so
	// 1.0-SNAPSHOT must not become 1.0-snapshot -- that is the corruption
	// the blanket rule caused and v0.9.0 removed.
	maven := mustDep(t, Coordinates{Ecosystem: EcosystemMaven, Org: "org.example", Name: "lib", Version: "1.0-SNAPSHOT"})
	if maven.Version != "1.0-SNAPSHOT" || maven.NodeID() != "pkg:maven/org.example/lib@1.0-SNAPSHOT" {
		t.Fatalf("maven: Version = %q, id = %q; want the case kept", maven.Version, maven.NodeID())
	}
}

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
			// A stated versionless package URL is an assertion too: the
			// constructor projects the empty version from it, so normalizing
			// has to clear the stale one rather than leave a version the
			// identity never claimed.
			name:   "a versionless identity clears a stale version",
			coords: Coordinates{PURL: "pkg:npm/foo", Version: "1.0.0"},
			want:   "",
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
