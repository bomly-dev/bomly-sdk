package sbom

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk/model"
)

// fipsOnlyProbe marks the child process of the test below.
const fipsOnlyProbe = "BOMLY_SDK_FIPS_ONLY_PROBE"

// Ingest must not crash where SHA-1 is unavailable.
//
// A Go runtime started with GODEBUG=fips140=only makes crypto/sha1 panic by
// design. The setting is read when the process starts, so it cannot be
// switched on inside a test: this test re-runs itself as a child with the
// setting applied and checks that a document still decodes there, without a
// checksum. A decoded document with no checksum is the intended outcome; a
// panic is the failure this guards against.
func TestIngestSurvivesAFIPSOnlyRuntime(t *testing.T) {
	if os.Getenv(fipsOnlyProbe) == "1" {
		doc, _, err := UnmarshalAutoJSON([]byte(documentRichSPDX))
		if err != nil {
			t.Fatalf("decode under fips140=only: %v", err)
		}
		if doc.Assertions.Checksum != nil {
			t.Fatalf("checksum = %+v under fips140=only, where SHA-1 cannot be computed", doc.Assertions.Checksum)
		}
		return
	}

	// Guard the guard: outside that mode the checksum is there, so the child's
	// "no checksum" is the mode's doing and not a checksum that is never set.
	doc, _, err := UnmarshalAutoJSON([]byte(documentRichSPDX))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.Assertions.Checksum == nil || doc.Assertions.Checksum.Algorithm != model.DigestAlgorithmSHA1 {
		t.Fatalf("checksum = %+v, want a SHA-1 in a normal runtime", doc.Assertions.Checksum)
	}

	child := exec.Command(os.Args[0], "-test.run=^TestIngestSurvivesAFIPSOnlyRuntime$", "-test.v")
	child.Env = append(os.Environ(), fipsOnlyProbe+"=1", "GODEBUG=fips140=only")
	output, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("ingest did not survive GODEBUG=fips140=only: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "PASS") {
		t.Fatalf("the child did not run the probe:\n%s", output)
	}
}
