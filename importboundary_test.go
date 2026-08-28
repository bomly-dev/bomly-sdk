package sdk

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// boundedImports lists third-party parsing libraries that may only be
// imported from their owning kit subpackage (ADR-0038 in bomly-cli's
// dev-docs/adr): the kit is the single home for that behavior, and a direct
// import elsewhere reintroduces the divergence the kit exists to end.
var boundedImports = []struct {
	module  string
	kitDir  string            // empty means only explicitly allowed files may import it
	allowed map[string]string // file (module-relative) -> reason
}{
	{
		module:  "github.com/package-url/packageurl-go",
		kitDir:  "purlkit",
		allowed: map[string]string{},
	},
	{
		// This fork remains only because the deprecated ParsePackageURL
		// signature exposes its concrete type. Remove both together in the
		// next coordinated minor release.
		module: "github.com/anchore/packageurl-go",
		allowed: map[string]string{
			// ParsePackageURL exposes the packageurl type in its signature;
			// the import goes when that deprecated function is removed in
			// the next coordinated breaking release.
			"purl.go": "deprecated ParsePackageURL keeps the type in its signature",
		},
	},
	{
		// The SPDX expression parser panics on some untrusted inputs;
		// spdxkit contains those panics, so no other package may reach the
		// parser directly.
		module:  "github.com/github/go-spdx",
		kitDir:  "spdxkit",
		allowed: map[string]string{},
	},
}

// TestThirdPartyParsersAreConfinedToTheirKits fails when a bounded library
// is imported outside its kit subpackage (test files included — a test that
// reaches around the kit hides the same divergence).
func TestThirdPartyParsersAreConfinedToTheirKits(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name := entry.Name(); strings.HasPrefix(name, ".") && name != "." {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imported := range file.Imports {
			value, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				continue
			}
			for _, bound := range boundedImports {
				if value != bound.module && !strings.HasPrefix(value, bound.module+"/") {
					continue
				}
				if bound.kitDir != "" && strings.HasPrefix(rel, bound.kitDir+string(filepath.Separator)) {
					continue
				}
				if _, ok := bound.allowed[rel]; ok {
					continue
				}
				if bound.kitDir == "" {
					t.Errorf("%s imports legacy module %s outside its explicit compatibility allowlist", rel, value)
					continue
				}
				t.Errorf("%s imports %s directly; that behavior belongs to %s/ (ADR-0038)", rel, value, bound.kitDir)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}
}
