package sdk

import (
	"os"
	"strings"
	"testing"
)

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
