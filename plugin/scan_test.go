package plugin

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeCommitSHA(t *testing.T) {
	for input, want := range map[string]string{
		"  0123ABCdef  ":        "0123abcdef",
		"0123abc":               "0123abc",
		"012345":                "",
		"main":                  "",
		"refs/heads/main":       "",
		"0123abcg":              "",
		"/tmp/checkout":         "",
		strings.Repeat("a", 64): strings.Repeat("a", 64),
		strings.Repeat("a", 65): "",
		"":                      "",
	} {
		if got := NormalizeCommitSHA(input); got != want {
			t.Errorf("NormalizeCommitSHA(%q) = %q, want %q", input, got, want)
		}
	}
	data, err := json.Marshal(ExecutionTarget{Kind: ExecutionTargetGitRepository, CommitSHA: "0123abc"})
	if err != nil || !strings.Contains(string(data), `"commitSha":"0123abc"`) {
		t.Fatalf("CommitSHA not encoded: %s %v", data, err)
	}
}
