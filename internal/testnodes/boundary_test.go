package testnodes_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testnodes builds fixtures and panics when one cannot be built, which is the
// right behaviour for a test and the wrong behaviour for a library. Nothing
// outside a test file may import it. A guard rather than a convention: the
// package is convenient enough that a production call site would look
// reasonable in review, and the failure mode -- a panic on coordinates the
// constructor refuses -- would reach every consumer of this module.
func TestTestnodesIsImportedOnlyByTests(t *testing.T) {
	const importPath = `"github.com/bomly-dev/bomly-sdk/internal/testnodes"`
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
		t.Fatalf("non-test code imports internal/testnodes; it panics on a fixture it cannot build: %v", offenders)
	}
}
