package sbom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Raw manifest values -- local paths, credentialed private-registry URLs --
// must be unreachable from the export layer. Export reads Origin.Normalized(),
// which is validated end to end; ResolvedURL is evidence, never output
// (bomly-cli ADR-0033). This is the structural answer to "could export
// accidentally leak the raw value": it cannot name it. The guard came here
// with the codec, and it fails when it scanned nothing, so a moved file
// cannot leave the rule silently (bomly-cli ADR-0044).
func TestExportNeverReadsResolvedURL(t *testing.T) {
	var offenders []string
	scanned := 0
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		if strings.Contains(string(body), "ResolvedURL") {
			offenders = append(offenders, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if scanned == 0 {
		t.Fatal("no Go files found in the sbom package; the guard scanned nothing")
	}
	if len(offenders) > 0 {
		t.Fatalf("the export layer references ResolvedURL; it must read Origin.Normalized() only: %v", offenders)
	}
}
