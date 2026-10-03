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

// The gate is in the codec: a managed component's payload cannot put a ref
// name or a padded hash where a commit goes, on either direction.
func TestExecutionTargetCodecAppliesTheCommitGate(t *testing.T) {
	var target ExecutionTarget
	if err := json.Unmarshal([]byte(`{"kind":"git-repository","repositoryUrl":" https://example.test/r.git ","ref":"main","commitSha":" 0123ABCDEF0123abcdef "}`), &target); err != nil {
		t.Fatal(err)
	}
	if target.CommitSHA != "0123abcdef0123abcdef" || target.RepositoryURL != "https://example.test/r.git" {
		t.Fatalf("decoded target = %+v", target)
	}
	data, err := json.Marshal(ExecutionTarget{Kind: ExecutionTargetGitRepository, Ref: "main", CommitSHA: "main"})
	if err != nil || string(data) != `{"kind":"git-repository","ref":"main"}` {
		t.Fatalf("encoded %s, %v; want the non-commit cleared", data, err)
	}
}
