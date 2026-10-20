package sbom

import (
	"encoding/json"
	"testing"

	"github.com/bomly-dev/bomly-sdk/model"
)

// vcsLocator is the one grammar both exports write for a repository origin:
// "git+<url>", and "@<revision>" after it when one is recorded.
func TestVCSLocator(t *testing.T) {
	cases := []struct {
		name       string
		repository string
		revision   string
		want       string
	}{
		{name: "pinned", repository: "https://github.com/facebook/react", revision: "b4c5d6e7", want: "git+https://github.com/facebook/react@b4c5d6e7"},
		{name: "unpinned", repository: "https://github.com/facebook/react", want: "git+https://github.com/facebook/react"},
		{name: "tag", repository: "https://github.com/actions/checkout", revision: "v4", want: "git+https://github.com/actions/checkout@v4"},
		{name: "whitespace is trimmed", repository: "  https://github.com/facebook/react ", revision: " v1 ", want: "git+https://github.com/facebook/react@v1"},
		{name: "no repository", revision: "v1", want: ""},
		{name: "nothing", want: ""},
	}
	for _, tc := range cases {
		if got := vcsLocator(tc.repository, tc.revision); got != tc.want {
			t.Errorf("%s: vcsLocator(%q, %q) = %q, want %q", tc.name, tc.repository, tc.revision, got, tc.want)
		}
	}
}

// A CycloneDX vcs reference is the locator only when there is a revision to
// carry; with nothing to pin it stays the location a reader can open.
func TestPinnedVCSReference(t *testing.T) {
	cases := []struct {
		name       string
		repository string
		revision   string
		want       string
	}{
		{name: "pinned", repository: "https://github.com/facebook/react", revision: "b4c5d6e7", want: "git+https://github.com/facebook/react@b4c5d6e7"},
		{name: "unpinned", repository: "https://github.com/facebook/react", want: "https://github.com/facebook/react"},
		{name: "blank revision", repository: "https://github.com/facebook/react", revision: "  ", want: "https://github.com/facebook/react"},
		{name: "no repository", revision: "v1", want: ""},
	}
	for _, tc := range cases {
		if got := pinnedVCSReference(tc.repository, tc.revision); got != tc.want {
			t.Errorf("%s: pinnedVCSReference(%q, %q) = %q, want %q", tc.name, tc.repository, tc.revision, got, tc.want)
		}
	}
}

// A pinned origin is one source, so it is one vcs reference: the locator
// carrying the revision, never that plus the plain URL beside it. The plain
// form used to be re-added from the component's single-valued repository
// field, which the first origin also fills.
func TestPinnedRepositoryOriginIsOneVCSReference(t *testing.T) {
	const (
		repository = "https://github.com/facebook/react"
		revision   = "b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7"
	)
	g := originGraph(t, func(_, pkg *model.DependencyNode) {
		pkg.Origins = model.MergeOrigins(nil, repositoryOriginsFor(repository, revision))
	})
	_, cdxRaw := marshalBoth(t, g)

	var doc struct {
		Components []struct {
			Name               string `json:"name"`
			ExternalReferences []struct {
				Type string `json:"type"`
				URL  string `json:"url"`
			} `json:"externalReferences"`
		} `json:"components"`
	}
	if err := json.Unmarshal(cdxRaw, &doc); err != nil {
		t.Fatalf("decode CycloneDX: %v", err)
	}
	for _, component := range doc.Components {
		if component.Name != "react" {
			continue
		}
		var vcs []string
		for _, ref := range component.ExternalReferences {
			if ref.Type == "vcs" {
				vcs = append(vcs, ref.URL)
			}
		}
		if len(vcs) != 1 || vcs[0] != "git+"+repository+"@"+revision {
			t.Fatalf("vcs references = %q, want exactly the pinned locator", vcs)
		}
		return
	}
	t.Fatal("react component not found")
}
