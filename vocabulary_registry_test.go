package sdk

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// These tests are the reason the SDK depends on the two format libraries
// rather than copying their vocabularies.
//
// Referencing a library constant makes a *rename* a compile error, which is
// most of the value. It does not catch an *addition*: a specification gains a
// member, the library adds a constant, and a hand-written table silently keeps
// rejecting documents that use it. That is not hypothetical — an earlier
// version of the digest registry omitted CycloneDX's Streebog algorithms, so
// a document carrying one had its digest dropped by the very gate that exists
// to keep unpublishable values out.
//
// So the libraries' own declarations are read and diffed against the registry.
// When cyclonedx-go or tools-golang adds a member, this fails and names it.

// declaredConstants returns every string constant of the named type declared
// in a package, keyed by the Go constant name.
func declaredConstants(t *testing.T, importPath, typeName string) map[string]string {
	t.Helper()
	dir := packageDir(t, importPath)
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", importPath, err)
	}
	found := map[string]string{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				genDecl, ok := decl.(*ast.GenDecl)
				if !ok || genDecl.Tok != token.CONST {
					continue
				}
				for _, spec := range genDecl.Specs {
					valueSpec, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					ident, ok := valueSpec.Type.(*ast.Ident)
					if !ok || ident.Name != typeName {
						continue
					}
					for i, name := range valueSpec.Names {
						if i >= len(valueSpec.Values) {
							continue
						}
						literal, ok := valueSpec.Values[i].(*ast.BasicLit)
						if !ok || literal.Kind != token.STRING {
							continue
						}
						unquoted, err := strconv.Unquote(literal.Value)
						if err != nil {
							continue
						}
						found[name.Name] = unquoted
					}
				}
			}
		}
	}
	if len(found) == 0 {
		t.Fatalf("no %s constants found in %s; the library's shape changed", typeName, importPath)
	}
	return found
}

// packageDir resolves a package's source directory in the module cache.
func packageDir(t *testing.T, importPath string) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-f", "{{.Dir}}", importPath).Output()
	if err != nil {
		t.Fatalf("locate %s (the go toolchain must be available): %v", importPath, err)
	}
	return filepath.Clean(strings.TrimSpace(string(out)))
}

// TestDigestRegistryCoversEveryLibraryAlgorithm fails when either library
// declares a hash algorithm the registry cannot resolve, which is what a
// specification adding a member looks like from here.
func TestDigestRegistryCoversEveryLibraryAlgorithm(t *testing.T) {
	for _, source := range []struct {
		importPath string
		typeName   string
		projection func(DigestAlgorithm) string
	}{
		{
			importPath: "github.com/spdx/tools-golang/spdx/v2/common",
			typeName:   "ChecksumAlgorithm",
			projection: DigestAlgorithm.SPDXName,
		},
		{
			importPath: "github.com/CycloneDX/cyclonedx-go",
			typeName:   "HashAlgorithm",
			projection: DigestAlgorithm.CycloneDXName,
		},
	} {
		t.Run(source.typeName, func(t *testing.T) {
			for constName, spelling := range declaredConstants(t, source.importPath, source.typeName) {
				algorithm, err := ParseDigestAlgorithm(spelling)
				if err != nil {
					t.Errorf("%s.%s = %q is not in the registry: %v", source.typeName, constName, spelling, err)
					continue
				}
				// The algorithm must also project back to that format under
				// exactly the library's spelling, or an export would emit a
				// value the format rejects.
				if got := source.projection(algorithm); got != spelling {
					t.Errorf("%s.%s = %q projects back as %q", source.typeName, constName, spelling, got)
				}
			}
		})
	}
}

// TestExternalReferenceVocabularyMatchesTheLibraries fails when SPDX declares
// a reference category or type the model does not account for.
func TestExternalReferenceVocabularyMatchesTheLibraries(t *testing.T) {
	const spdxCommon = "github.com/spdx/tools-golang/spdx/v2/common"
	declared := declaredConstants(t, spdxCommon, "string")

	for constName, spelling := range declared {
		switch {
		case strings.HasPrefix(constName, "Category"):
			category, err := ParseExternalReferenceCategory(spelling)
			if err != nil {
				t.Errorf("%s = %q is not a known category: %v", constName, spelling, err)
				continue
			}
			if got := category.SPDXName(); got != spelling {
				t.Errorf("%s = %q projects back as %q", constName, spelling, got)
			}
		case strings.HasPrefix(constName, "TypeSecurity"),
			strings.HasPrefix(constName, "TypePackageManager"),
			strings.HasPrefix(constName, "TypePersistentId"):
			// Every reference type the specification names must have a
			// locator kind decided by the table rather than falling through
			// to the identifier default, which would validate a URL or a
			// package URL as a bare token.
			category := categoryForTypeConstant(constName)
			if _, mapped := locatorKindByReference[category][normalizeReferenceType(spelling)]; !mapped {
				t.Errorf("%s = %q has no locator kind; it would fall through to the identifier default", constName, spelling)
			}
		}
	}
}

// TestCycloneDXReferenceTypesAreCanonicalized fails when cyclonedx-go
// declares a reference type the canonical registry does not hold. A constant
// reference makes a rename a compile error; only this catches an addition,
// and an uncanonicalized type publishes whichever spelling folded first.
func TestCycloneDXReferenceTypesAreCanonicalized(t *testing.T) {
	declared := declaredConstants(t, "github.com/CycloneDX/cyclonedx-go", "ExternalReferenceType")
	for constName, spelling := range declared {
		// Membership is asserted directly. canonicalReferenceType returns
		// its input when the key is absent -- the open vocabulary carries an
		// unrecognized type unchanged -- so comparing its output to the
		// spelling cannot detect a missing entry at all. That first draft
		// rested entirely on the upper-case probe, which only distinguishes
		// the two when uppercasing changes the string.
		canonical, present := canonicalCycloneDXReferenceTypes[normalizeReferenceType(spelling)]
		if !present {
			t.Errorf("%s = %q is missing from the CycloneDX registry", constName, spelling)
			continue
		}
		if canonical != spelling {
			t.Errorf("%s = %q is registered as %q", constName, spelling, canonical)
		}
		// And a differently-cased spelling folds to the library's own.
		if got := canonicalReferenceType(ExternalReferenceCategoryUnknown, strings.ToUpper(spelling)); got != spelling {
			t.Errorf("%s: upper-cased %q canonicalizes to %q, want %q", constName, spelling, got, spelling)
		}
	}
}

// categoryForTypeConstant maps the library's constant-naming convention to the
// category the type belongs to.
func categoryForTypeConstant(constName string) ExternalReferenceCategory {
	switch {
	case strings.HasPrefix(constName, "TypeSecurity"):
		return ExternalReferenceCategorySecurity
	case strings.HasPrefix(constName, "TypePackageManager"):
		return ExternalReferenceCategoryPackageManager
	case strings.HasPrefix(constName, "TypePersistentId"):
		return ExternalReferenceCategoryPersistentID
	default:
		return ExternalReferenceCategoryUnknown
	}
}
