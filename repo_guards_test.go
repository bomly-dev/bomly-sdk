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

// boundedImports lists parsing libraries that may only be imported from their
// owning subpackage (ADR-0038 in bomly-cli's dev-docs/adr): that package is
// the single home for the behavior, and a direct import elsewhere
// reintroduces the divergence it exists to end. The strict JSON readers are
// bounded the same way for the opposite reason (ADR-0039): the SBOM codec
// refuses an ambiguous document on purpose, and the plugin wire in the root
// package must keep decoding leniently, so nothing outside sbom/ may reach
// for a reader that would tighten it by accident.
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
		// PEP 440 canonical versions are part of what a pypi identity is,
		// and purlkit's normalization step is where every identity passes;
		// a second caller would fold versions on one path and not another.
		module:  "github.com/aquasecurity/go-pep440-version",
		kitDir:  "purlkit",
		allowed: map[string]string{},
	},
	{
		// The SPDX expression parser panics on some untrusted inputs;
		// spdxkit contains those panics, so no other package may reach the
		// parser directly.
		module:  "github.com/github/go-spdx",
		kitDir:  "spdxkit",
		allowed: map[string]string{},
	},
	{
		module:  "encoding/json/v2",
		kitDir:  "sbom",
		allowed: map[string]string{},
	},
	{
		module:  "encoding/json/jsontext",
		kitDir:  "sbom",
		allowed: map[string]string{},
	},
	{
		// The HashiCorp go-plugin transport is the managed-plugin runtime
		// and nothing else. Both ends of the handshake -- HandshakeConfig
		// and ClientPluginMap on the host side, Serve* on the plugin side
		// -- live in plugin/, so a second importer is a second place the
		// magic cookie or the plugin map could drift from what the other
		// end expects.
		module: "github.com/hashicorp/go-plugin",
		kitDir: "runtime",
		allowed: map[string]string{
			"conformance/conformance.go": "ProbeBinary launches the built plugin binary over the real transport, exactly as the host does",
		},
	},
	{
		// gRPC is the wire beneath go-plugin. The bomly.plugin.v1 service
		// -- its method names, status codes, and BytesValue envelopes -- is
		// declared once in plugin/; a direct import elsewhere puts protocol
		// shape outside the file that owns it.
		module:  "google.golang.org/grpc",
		kitDir:  "runtime",
		allowed: map[string]string{},
	},
	{
		// The protobuf well-known types are the envelopes of that service
		// and travel with it.
		module:  "google.golang.org/protobuf",
		kitDir:  "runtime",
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

// AGENTS.md and CLAUDE.md are maintained as copies of each other, and the
// files say so in their own first lines. Nothing enforced it until now, and
// the gap was not theoretical: the note declining the embedlit modernizer
// analyzer went into one file and not the other, so an agent reading the
// other one would have re-applied the 43 hunks that note exists to prevent.
//
// Only the title differs, because each file names itself.
func TestGuidanceFilesStayInSync(t *testing.T) {
	const (
		agents = "AGENTS.md"
		claude = "CLAUDE.md"
	)
	agentsBody, err := os.ReadFile(agents)
	if err != nil {
		t.Fatalf("read %s: %v", agents, err)
	}
	claudeBody, err := os.ReadFile(claude)
	if err != nil {
		t.Fatalf("read %s: %v", claude, err)
	}

	agentsLines := strings.SplitN(string(agentsBody), "\n", 2)
	claudeLines := strings.SplitN(string(claudeBody), "\n", 2)
	if agentsLines[0] != "# AGENTS.md" || claudeLines[0] != "# CLAUDE.md" {
		t.Fatalf("titles are %q and %q; this test assumes each file names itself on line one",
			agentsLines[0], claudeLines[0])
	}
	if len(agentsLines) != 2 || len(claudeLines) != 2 {
		t.Fatalf("one of the guidance files is a single line")
	}
	if agentsLines[1] != claudeLines[1] {
		t.Errorf("%s and %s have drifted below their titles. They are copies of each other by "+
			"design, so guidance added to one and not the other is guidance an agent reading the "+
			"other will not follow. Copy the change across.", agents, claude)
	}
}
