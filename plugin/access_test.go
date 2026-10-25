package plugin

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestAccessNormalizesAndCanonicalizes(t *testing.T) {
	access := Access{
		FilesystemRead: []FilesystemScope{FilesystemProject, FilesystemCache, FilesystemProject},
		Network:        []string{"API.OSV.dev", "*.GitHub.com", "例え.テスト", "api.osv.dev", "*"},
		Environment:    []string{"GITHUB_TOKEN", "BOMLY_HTTP_*", "GITHUB_TOKEN"},
		Subprocesses:   []string{"npm", "go", "go"},
	}
	got := access.Normalized()
	want := Access{
		FilesystemRead: []FilesystemScope{FilesystemCache, FilesystemProject},
		Network:        []string{"*", "*.github.com", "api.osv.dev", "xn--r8jz45g.xn--zckzah"},
		Environment:    []string{"BOMLY_HTTP_*", "GITHUB_TOKEN"},
		Subprocesses:   []string{"go", "npm"},
	}
	if !accessEqual(got, want) {
		t.Errorf("Normalized =\n%+v\nwant\n%+v", got, want)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("normalized disclosure does not validate: %v", err)
	}
}

func accessEqual(a, b Access) bool {
	return slices.Equal(a.FilesystemRead, b.FilesystemRead) && slices.Equal(a.FilesystemWrite, b.FilesystemWrite) &&
		slices.Equal(a.Network, b.Network) && slices.Equal(a.Environment, b.Environment) && slices.Equal(a.Subprocesses, b.Subprocesses)
}

func TestAccessValidate(t *testing.T) {
	valid := []Access{
		{},
		{FilesystemRead: []FilesystemScope{"future-scope"}},
		{Network: []string{"*", "*.github.com", "api.osv.dev"}},
		{Environment: []string{"*", "_PRIVATE", "BOMLY_*"}},
		{Subprocesses: []string{"*", "go", "mvn.cmd"}},
	}
	for _, access := range valid {
		if err := access.Validate(); err != nil {
			t.Errorf("Validate(%+v) = %v", access, err)
		}
	}
	tooMany := make([]string, MaxAccessEntries+1)
	for i := range tooMany {
		tooMany[i] = "go"
	}
	invalid := []Access{
		{FilesystemRead: []FilesystemScope{"/etc/passwd"}},
		{FilesystemWrite: []FilesystemScope{"Project"}},
		{Network: []string{"https://api.osv.dev"}},
		{Network: []string{"api.osv.dev:443"}},
		{Network: []string{"*."}},
		{Network: []string{"**.example.com"}},
		{Network: []string{strings.Repeat("a", 64) + ".example"}},
		{Environment: []string{"1PASSWORD"}},
		{Environment: []string{"GITHUB_TOKEN=secret"}},
		{Environment: []string{"A*B"}},
		{Subprocesses: []string{"/usr/bin/go"}},
		{Subprocesses: []string{"go build"}},
		{Subprocesses: []string{".."}},
		{Subprocesses: []string{"go\x00"}},
		{Subprocesses: tooMany},
	}
	for _, access := range invalid {
		if err := access.Validate(); err == nil {
			t.Errorf("Validate(%+v) accepted a malformed disclosure", access)
		}
	}
	if ValidateAccess(nil) != nil {
		t.Error("an absent disclosure -- unknown -- must be valid")
	}
	if ValidateAccess(&Access{Network: []string{"bad host"}}) == nil {
		t.Error("ValidateAccess accepted a malformed present disclosure")
	}
}

// TestAccessAbsentAndEmptyEncodeApart pins the distinction a host's UI
// depends on: no block is unknown, an empty block claims no access.
func TestAccessAbsentAndEmptyEncodeApart(t *testing.T) {
	type manifest struct {
		Access *Access `json:"access,omitempty"`
	}
	absent, err := json.Marshal(manifest{})
	if err != nil {
		t.Fatal(err)
	}
	empty, err := json.Marshal(manifest{Access: &Access{}})
	if err != nil {
		t.Fatal(err)
	}
	if string(absent) != `{}` || string(empty) != `{"access":{}}` {
		t.Errorf("absent = %s, empty = %s", absent, empty)
	}
	var decoded manifest
	if err := json.Unmarshal([]byte(`{}`), &decoded); err != nil || decoded.Access != nil {
		t.Errorf("an absent block decodes as %+v, %v; want nil (unknown)", decoded.Access, err)
	}
	if err := json.Unmarshal([]byte(`{"access":{"network":["API.OSV.dev","api.osv.dev"]}}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Access == nil || !slices.Equal(decoded.Access.Network, []string{"api.osv.dev"}) {
		t.Errorf("decoded %+v; want the normalized destination", decoded.Access)
	}
}

// FuzzAccess holds the disclosure codec to its contract on arbitrary
// manifest input: it never panics, a disclosure that validates is a fixed
// point of encode and decode, and normalization never turns a valid
// disclosure invalid.
func FuzzAccess(f *testing.F) {
	for _, seed := range []string{
		`{}`,
		`{"filesystemRead":["project","cache"],"filesystemWrite":["temp"]}`,
		`{"network":["*","*.github.com","API.osv.dev","例え.テスト"]}`,
		`{"environment":["GITHUB_TOKEN","BOMLY_*"],"subprocesses":["go","npm"]}`,
		`{"network":["*.","a..b","xn--"],"environment":["1X"],"subprocesses":["../x"]}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		var access Access
		if err := json.Unmarshal(data, &access); err != nil {
			return
		}
		if access.Validate() != nil {
			return
		}
		first, err := json.Marshal(access)
		if err != nil {
			t.Fatalf("marshal a valid disclosure: %v", err)
		}
		var again Access
		if err := json.Unmarshal(first, &again); err != nil {
			t.Fatalf("decode own output %s: %v", first, err)
		}
		if err := again.Validate(); err != nil {
			t.Fatalf("own output %s no longer validates: %v", first, err)
		}
		second, err := json.Marshal(again)
		if err != nil {
			t.Fatal(err)
		}
		if string(first) != string(second) {
			t.Fatalf("not a fixed point:\n%s\n%s", first, second)
		}
	})
}
