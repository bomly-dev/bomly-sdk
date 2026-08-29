package sdk

import (
	"encoding/json"
	"strings"
	"testing"
)

// sameLocation reports whether two origins normalize to one location. With no
// merge logic in the model, "two spellings of one place" is expressed as
// canonical-form equality rather than as a reconciliation outcome.
func sameLocation(left, right *DependencyOrigin) bool {
	l, r := left.Normalized(), right.Normalized()
	if l == nil || r == nil {
		return l == r
	}
	return *l == *r
}

func TestArtifactOrigin(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{name: "registry tarball", raw: "https://registry.npmjs.org/react/-/react-18.2.0.tgz", want: "https://registry.npmjs.org/react/-/react-18.2.0.tgz"},
		{name: "checksum fragment is stripped", raw: "https://registry.npmjs.org/react/-/react-18.2.0.tgz#ceeba773e3e9d2b6f1a2b6b9f4f1cb2f9c2e1a55", want: "https://registry.npmjs.org/react/-/react-18.2.0.tgz"},
		{name: "uppercase scheme is normalized", raw: "HTTPS://files.pythonhosted.org/packages/x/django-5.0.tar.gz", want: "https://files.pythonhosted.org/packages/x/django-5.0.tar.gz"},
		{name: "signed link carrying a query", raw: "https://nexus.corp/repo/pkg.tgz?token=abc123"},
		{name: "embedded credentials", raw: "https://user:s3cret@nexus.corp/repo/pkg.tgz"}, //nolint:gosec // synthetic credential; rejecting it is the rule under test
		{name: "registry root", raw: "https://registry.npmjs.org/"},
		{name: "relative path", raw: "packages/lib"},
		{name: "absolute local path", raw: "/Users/someone/src/project"},
		{name: "file url", raw: "file:///home/someone/wheels/pkg.whl"},
		{name: "git+ssh remote", raw: "git+ssh://git@github.com/owner/repo.git#9f8e7d6"},
		{name: "git+https prefix", raw: "git+https://github.com/owner/repo.git"},
		{name: "scp-style remote", raw: "git@github.com:owner/repo.git"},
		{name: "windows path", raw: `C:\src\project`},
		{name: "malformed host", raw: "https://:8080/pkg.tgz"},
		{name: "non-web scheme", raw: "ftp://files.example.com/pkg.tgz"},
		{name: "empty", raw: "   "},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			origin := ArtifactOrigin(tc.raw)
			if tc.want == "" {
				if origin != nil {
					t.Fatalf("origin = %+v, want nil", origin)
				}
				return
			}
			if origin == nil {
				t.Fatalf("origin = nil, want artifact %q", tc.want)
			}
			if origin.ArtifactURL != tc.want {
				t.Fatalf("artifact = %q, want %q", origin.ArtifactURL, tc.want)
			}
			if origin.Repository != "" || origin.Revision != "" {
				t.Fatalf("artifact origin carries repository data: %+v", origin)
			}
		})
	}
}

func TestRepositoryOrigin(t *testing.T) {
	cases := []struct {
		name         string
		raw          string
		revision     string
		wantRepo     string
		wantRevision string
	}{
		{
			name:         "repository with resolved commit",
			raw:          "https://github.com/owner/repo.git",
			revision:     "9f8e7d6c5b4a3928176554433221100ffeeddcc0",
			wantRepo:     "https://github.com/owner/repo.git",
			wantRevision: "9f8e7d6c5b4a3928176554433221100ffeeddcc0",
		},
		{
			name:         "requested ref is dropped for the resolved one",
			raw:          "https://github.com/example/helper?rev=main#abc123",
			revision:     "0a1b2c3d4e5f60718293a4b5c6d7e8f901234567",
			wantRepo:     "https://github.com/example/helper",
			wantRevision: "0a1b2c3d4e5f60718293a4b5c6d7e8f901234567",
		},
		{name: "tag pin", raw: "https://github.com/owner/repo", revision: "v1.2.3", wantRepo: "https://github.com/owner/repo", wantRevision: "v1.2.3"},
		{name: "branch-style ref", raw: "https://github.com/owner/repo", revision: "release/2026-08", wantRepo: "https://github.com/owner/repo", wantRevision: "release/2026-08"},
		{name: "unpinned repository", raw: "https://github.com/owner/repo", wantRepo: "https://github.com/owner/repo"},
		{name: "revision breaking a locator grammar", raw: "https://github.com/owner/repo", revision: "feature@login", wantRepo: "https://github.com/owner/repo"},
		{name: "whitespace revision", raw: "https://github.com/owner/repo", revision: "not a revision", wantRepo: "https://github.com/owner/repo"},
		{name: "overlong revision", raw: "https://github.com/owner/repo", revision: strings.Repeat("a", 129), wantRepo: "https://github.com/owner/repo"},
		{name: "bare host", raw: "https://github.com", revision: "9f8e7d6"},
		{name: "index root", raw: "https://index.crates.io/", revision: "9f8e7d6"},
		{name: "credentialed remote", raw: "https://oauth2:glpat-xxxxxxxxxxxxxxxxxxxx@gitlab.corp/team/repo.git", revision: "9f8e7d6"}, //nolint:gosec // synthetic credential; rejecting it is the rule under test
		{name: "ssh remote", raw: "ssh://github.com/owner/repo.git", revision: "9f8e7d6"},
		{name: "local checkout", raw: "/Users/someone/src/repo", revision: "9f8e7d6"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			origin := RepositoryOrigin(tc.raw, tc.revision)
			if tc.wantRepo == "" {
				if origin != nil {
					t.Fatalf("origin = %+v, want nil", origin)
				}
				return
			}
			if origin == nil {
				t.Fatalf("origin = nil, want repository %q", tc.wantRepo)
			}
			if origin.Repository != tc.wantRepo || origin.Revision != tc.wantRevision {
				t.Fatalf("origin = %+v, want repository %q revision %q", origin, tc.wantRepo, tc.wantRevision)
			}
			if origin.ArtifactURL != "" {
				t.Fatalf("repository origin carries an artifact URL: %q", origin.ArtifactURL)
			}
		})
	}
}

// Origin can reach a consumer from a plugin or a hand-built graph that never
// went through the constructors, so reading re-validates.
func TestDependencyOriginNormalized(t *testing.T) {
	cases := []struct {
		name   string
		origin *DependencyOrigin
		want   *DependencyOrigin
	}{
		{name: "nil"},
		{name: "empty", origin: &DependencyOrigin{}},
		{name: "credentialed artifact", origin: &DependencyOrigin{ArtifactURL: "https://build:s3cret@nexus.corp/pkg.tgz"}}, //nolint:gosec // synthetic credential; rejecting it is the rule under test
		{name: "local repository", origin: &DependencyOrigin{Repository: "file:///home/someone/repo"}},
		{name: "revision without a repository", origin: &DependencyOrigin{Revision: "9f8e7d6"}},
		{
			name:   "artifact wins over repository",
			origin: &DependencyOrigin{ArtifactURL: "https://registry.npmjs.org/react/-/react-18.2.0.tgz", Repository: "https://github.com/facebook/react"},
			want:   &DependencyOrigin{ArtifactURL: "https://registry.npmjs.org/react/-/react-18.2.0.tgz"},
		},
		{
			name:   "query and fragment are stripped from a hand-built repository",
			origin: &DependencyOrigin{Repository: "https://github.com/owner/repo?rev=main#abc", Revision: "9f8e7d6"},
			want:   &DependencyOrigin{Repository: "https://github.com/owner/repo", Revision: "9f8e7d6"},
		},
		{
			name:   "unusable revision is dropped, repository kept",
			origin: &DependencyOrigin{Repository: "https://github.com/owner/repo", Revision: "feature@login"},
			want:   &DependencyOrigin{Repository: "https://github.com/owner/repo"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.origin.Normalized()
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("normalized = %+v, want nil", got)
			case tc.want != nil && got == nil:
				t.Fatalf("normalized = nil, want %+v", tc.want)
			case tc.want != nil && *got != *tc.want:
				t.Fatalf("normalized = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// Hosts are case-insensitive. Two producers writing one host differently name
// the same place, and must not reconcile to a disagreement.
func TestDependencyOriginHostCaseIsCanonical(t *testing.T) {
	upper := RepositoryOrigin("https://GitHub.com/Owner/Repo", "aaaabbbbccccddddeeeeffff0000111122223333")
	lower := RepositoryOrigin("https://github.com/Owner/Repo", "aaaabbbbccccddddeeeeffff0000111122223333")

	if upper == nil || lower == nil {
		t.Fatal("both spellings should be publishable")
	}
	if upper.Repository != "https://github.com/Owner/Repo" {
		t.Fatalf("repository = %q, want a lowercased host and an untouched path", upper.Repository)
	}
	if !sameLocation(upper, lower) {
		t.Fatal("two spellings of one host must normalize to one location")
	}

	// The path is case-sensitive, so these stay different locations.
	if sameLocation(
		ArtifactOrigin("https://example.test/Pkg-1.0.0.tgz"),
		ArtifactOrigin("https://example.test/pkg-1.0.0.tgz"),
	) {
		t.Fatal("paths differing in case are different locations")
	}
}

// An explicit default port names the same origin as no port at all.
func TestDependencyOriginDefaultPortIsCanonical(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{name: "https default port", raw: "https://example.test:443/pkg-1.0.0.tgz", want: "https://example.test/pkg-1.0.0.tgz"},
		{name: "http default port", raw: "http://example.test:80/pkg-1.0.0.tgz", want: "http://example.test/pkg-1.0.0.tgz"},
		{name: "a non-default port is part of the location", raw: "https://example.test:8443/pkg-1.0.0.tgz", want: "https://example.test:8443/pkg-1.0.0.tgz"},
		{name: "the highest usable port", raw: "https://example.test:65535/pkg-1.0.0.tgz", want: "https://example.test:65535/pkg-1.0.0.tgz"},
		{name: "a default port written with leading zeros", raw: "https://example.test:0443/pkg-1.0.0.tgz", want: "https://example.test/pkg-1.0.0.tgz"},
		{name: "an http default port with leading zeros", raw: "http://example.test:080/pkg-1.0.0.tgz", want: "http://example.test/pkg-1.0.0.tgz"},
		{name: "leading zeros on any port are normalized", raw: "https://example.test:08443/pkg-1.0.0.tgz", want: "https://example.test:8443/pkg-1.0.0.tgz"},
		{name: "an IPv6 literal keeps its brackets", raw: "https://[2001:db8::1]:443/pkg-1.0.0.tgz", want: "https://[2001:db8::1]/pkg-1.0.0.tgz"},
		{name: "an IPv6 literal keeps its brackets on a rewritten port", raw: "https://[2001:db8::1]:08443/pkg-1.0.0.tgz", want: "https://[2001:db8::1]:8443/pkg-1.0.0.tgz"},
		{name: "an IPv4-mapped literal keeps its brackets", raw: "https://[::ffff:192.0.2.1]:0443/pkg-1.0.0.tgz", want: "https://[::ffff:192.0.2.1]/pkg-1.0.0.tgz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			origin := ArtifactOrigin(tc.raw)
			if origin == nil {
				t.Fatalf("origin = nil, want %q", tc.want)
			}
			if origin.ArtifactURL != tc.want {
				t.Fatalf("artifact = %q, want %q", origin.ArtifactURL, tc.want)
			}
		})
	}

	if !sameLocation(
		ArtifactOrigin("https://example.test:443/pkg-1.0.0.tgz"),
		ArtifactOrigin("https://example.test/pkg-1.0.0.tgz"),
	) {
		t.Fatal("a default port must normalize away")
	}
	if !sameLocation(
		ArtifactOrigin("https://example.test:0443/pkg-1.0.0.tgz"),
		ArtifactOrigin("https://example.test/pkg-1.0.0.tgz"),
	) {
		t.Fatal("a default port written with leading zeros must normalize away")
	}
	if !sameLocation(
		ArtifactOrigin("https://example.test:08443/pkg-1.0.0.tgz"),
		ArtifactOrigin("https://example.test:8443/pkg-1.0.0.tgz"),
	) {
		t.Fatal("one port written two ways must normalize to one location")
	}
	if sameLocation(
		ArtifactOrigin("https://example.test:8443/pkg-1.0.0.tgz"),
		ArtifactOrigin("https://example.test/pkg-1.0.0.tgz"),
	) {
		t.Fatal("a non-default port is a different location")
	}
}

// Empty and Normalized must answer one question, so a caller that guards on
// Empty can read Normalized without a second nil check.
func TestDependencyOriginEmptyAgreesWithNormalized(t *testing.T) {
	origins := []*DependencyOrigin{
		nil,
		{},
		{ArtifactURL: "https://registry.npmjs.org/react/-/react-18.2.0.tgz"},
		{ArtifactURL: "/Users/someone/pkg.tgz"},
		{Repository: "file:///home/someone/repo"},
		{Repository: "https://github.com/owner/repo", Revision: "feature@login"},
		{Revision: "9f8e7d6"},
	}
	for _, origin := range origins {
		if origin.Empty() != (origin.Normalized() == nil) {
			t.Fatalf("Empty() and Normalized() disagree for %+v", origin)
		}
	}
}

func TestDependencyOriginEmpty(t *testing.T) {
	var nilOrigin *DependencyOrigin
	if !nilOrigin.Empty() {
		t.Fatal("nil origin should be empty")
	}
	if !(&DependencyOrigin{}).Empty() {
		t.Fatal("zero origin should be empty")
	}
	if (&DependencyOrigin{ArtifactURL: "https://example.test/pkg.tgz"}).Empty() {
		t.Fatal("artifact origin should not be empty")
	}
}

// Cloning a dependency must not leave the copies sharing origin state.
func TestDependencyCloneCopiesOrigin(t *testing.T) {
	dep := mustDep(t, Coordinates{Name: "react", Version: "18.2.0"})
	dep.Origins = MergeOrigins(nil, []DependencyOrigin{*ArtifactOrigin("https://registry.npmjs.org/react/-/react-18.2.0.tgz")})
	clone := dep.Clone()
	clone.Origins[0].ArtifactURL = "https://npm.corp/mirror/react/-/react-18.2.0.tgz"

	if dep.Origins[0].ArtifactURL != "https://registry.npmjs.org/react/-/react-18.2.0.tgz" {
		t.Fatalf("mutating a clone changed the original: %+v", dep.Origins)
	}
}

// The wire contract is additive: an origin-bearing payload round-trips, and a
// payload from a build that predates the field still decodes.
func TestDependencyOriginWireRoundTrip(t *testing.T) {
	dep := mustDep(t, Coordinates{Name: "react", Version: "18.2.0"})
	dep.Origins = MergeOrigins(nil, []DependencyOrigin{
		*RepositoryOrigin("https://github.com/facebook/react", "b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7"),
	})
	raw, err := json.Marshal(dep)
	if err != nil {
		t.Fatal(err)
	}
	var decoded DependencyNode
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Origins) != 1 || decoded.Origins[0] != dep.Origins[0] {
		t.Fatalf("decoded origins = %+v, want %+v", decoded.Origins, dep.Origins)
	}

	var legacy DependencyNode
	if err := json.Unmarshal([]byte(`{"id":"react@18.2.0","name":"react","version":"18.2.0"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Origins != nil {
		t.Fatalf("origins = %+v, want nil for a payload that predates the field", legacy.Origins)
	}
	if raw, err := json.Marshal(legacy); err != nil || strings.Contains(string(raw), "origin") {
		t.Fatalf("an absent origin must not be serialized: %s (err %v)", raw, err)
	}
}

// RFC 3986: an escaped unreserved character means the same as the character,
// so two spellings of one path must not read as a disagreement. Reserved
// characters keep their escapes, because there the escape changes the meaning.
func TestDependencyOriginPercentEncodingIsCanonical(t *testing.T) {
	cases := []struct{ name, raw, want string }{
		{name: "escaped tilde", raw: "https://example.test/pkg/%7Euser/a.tgz", want: "https://example.test/pkg/~user/a.tgz"},
		{name: "escaped letter", raw: "https://example.test/%70kg/a.tgz", want: "https://example.test/pkg/a.tgz"},
		{name: "lowercase hex is uppercased", raw: "https://example.test/pkg/a%2fb.tgz", want: "https://example.test/pkg/a%2Fb.tgz"},
		{name: "a reserved escape keeps its meaning", raw: "https://example.test/pkg/a%2Fb.tgz", want: "https://example.test/pkg/a%2Fb.tgz"},
		{name: "a space stays escaped", raw: "https://example.test/pkg/a%20b.tgz", want: "https://example.test/pkg/a%20b.tgz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			origin := ArtifactOrigin(tc.raw)
			if origin == nil {
				t.Fatalf("origin = nil, want %q", tc.want)
			}
			if origin.ArtifactURL != tc.want {
				t.Fatalf("artifact = %q, want %q", origin.ArtifactURL, tc.want)
			}
		})
	}

	// url.Parse accepts any numeric port, but nothing can connect to these.
	for _, raw := range []string{
		"https://example.test:99999/pkg-1.0.0.tgz",
		"https://example.test:0/pkg-1.0.0.tgz",
		"https://example.test:65536/pkg-1.0.0.tgz",
	} {
		if origin := ArtifactOrigin(raw); origin != nil {
			t.Errorf("origin = %+v for %q, want nil: the port is outside the usable range", origin, raw)
		}
	}

	// A malformed escape is not a location anything can fetch.
	if origin := ArtifactOrigin("https://example.test/pkg/100%.tgz"); origin != nil {
		t.Fatalf("origin = %+v, want nil for a malformed escape", origin)
	}

	if !sameLocation(
		ArtifactOrigin("https://example.test/pkg/%7Euser/a.tgz"),
		ArtifactOrigin("https://example.test/pkg/~user/a.tgz"),
	) {
		t.Fatal("two spellings of one path must normalize to one location")
	}
	if sameLocation(
		ArtifactOrigin("https://example.test/pkg/a%2Fb.tgz"),
		ArtifactOrigin("https://example.test/pkg/a/b.tgz"),
	) {
		t.Fatal("an escaped slash is a different path")
	}
}

// A value that would be rejected on read must not be storable or forwardable.
func TestDependencyOriginNormalizesAcrossJSON(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want DependencyOrigin
	}{
		{name: "credentialed artifact is dropped", raw: `{"artifact_url":"https://build:s3cret@nexus.corp/pkg.tgz"}`}, //nolint:gosec // synthetic credential; rejecting it is the rule under test
		{name: "local path is dropped", raw: `{"repository":"file:///home/someone/repo"}`},
		{name: "revision without a repository is dropped", raw: `{"revision":"9f8e7d6"}`},
		{
			name: "a publishable value survives",
			raw:  `{"artifact_url":"https://registry.npmjs.org/react/-/react-18.2.0.tgz"}`,
			want: DependencyOrigin{ArtifactURL: "https://registry.npmjs.org/react/-/react-18.2.0.tgz"},
		},
		{
			name: "host casing is canonicalized in transit",
			raw:  `{"repository":"https://GitHub.com/Owner/Repo","revision":"aaaabbbbccccddddeeeeffff0000111122223333"}`,
			want: DependencyOrigin{Repository: "https://github.com/Owner/Repo", Revision: "aaaabbbbccccddddeeeeffff0000111122223333"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var decoded DependencyOrigin
			if err := json.Unmarshal([]byte(tc.raw), &decoded); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if decoded != tc.want {
				t.Fatalf("decoded = %+v, want %+v", decoded, tc.want)
			}
		})
	}

	// The same rule applies leaving the process, so a hand-built value cannot
	// be written out either.
	raw, err := json.Marshal(&DependencyOrigin{ArtifactURL: "https://build:s3cret@nexus.corp/pkg.tgz"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "s3cret") {
		t.Fatalf("marshaled %s, which carries a credential", raw)
	}
}

// Graph merging unions origins: gap-fill is gone (ADR-0041) — Origins is a
// deduplicated union list, so an origin survives regardless of manifest order
// and two disagreeing witnesses both stay visible instead of one winning.
func TestMergeGraphUnionsOrigins(t *testing.T) {
	const (
		artifact = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
		mirror   = "https://npm.corp/mirror/lodash/-/lodash-4.17.21.tgz"
		mergedID = "pkg:npm/lodash@4.17.21"
	)
	build := func(t *testing.T, url string) *Graph {
		t.Helper()
		g := New()
		node := mustDep(t, Coordinates{Name: "lodash", Version: "4.17.21", Ecosystem: EcosystemNPM})
		if url != "" {
			node.Origins = MergeOrigins(nil, []DependencyOrigin{*ArtifactOrigin(url)})
		}
		if err := g.AddNode(node); err != nil {
			t.Fatal(err)
		}
		return g
	}
	originsOf := func(t *testing.T, g *Graph) []DependencyOrigin {
		t.Helper()
		node, ok := g.DependencyNode(mergedID)
		if !ok {
			t.Fatal("expected lodash in the merged graph")
		}
		return node.Origins
	}

	t.Run("a later record fills the gap", func(t *testing.T) {
		merged := New()
		if err := MergeGraph(merged, build(t, "")); err != nil {
			t.Fatal(err)
		}
		if err := MergeGraph(merged, build(t, artifact)); err != nil {
			t.Fatal(err)
		}
		if got := originsOf(t, merged); len(got) != 1 || got[0].ArtifactURL != artifact {
			t.Fatalf("merged origins = %+v, want %q regardless of manifest order", got, artifact)
		}
	})

	t.Run("an earlier record's origin survives a bare witness", func(t *testing.T) {
		merged := New()
		if err := MergeGraph(merged, build(t, artifact)); err != nil {
			t.Fatal(err)
		}
		if err := MergeGraph(merged, build(t, "")); err != nil {
			t.Fatal(err)
		}
		if got := originsOf(t, merged); len(got) != 1 || got[0].ArtifactURL != artifact {
			t.Fatalf("merged origins = %+v, want %q", got, artifact)
		}
	})

	// Two disagreeing witnesses union instead of the existing one winning —
	// the shape of a dependency-confusion signal stays observable.
	t.Run("disagreeing origins union", func(t *testing.T) {
		merged := New()
		if err := MergeGraph(merged, build(t, artifact)); err != nil {
			t.Fatal(err)
		}
		if err := MergeGraph(merged, build(t, mirror)); err != nil {
			t.Fatal(err)
		}
		got := originsOf(t, merged)
		if len(got) != 2 || got[0].ArtifactURL != artifact || got[1].ArtifactURL != mirror {
			t.Fatalf("merged origins = %+v, want the union [%q, %q]", got, artifact, mirror)
		}
	})
}

func TestMergeOrigins(t *testing.T) {
	registry := DependencyOrigin{ArtifactURL: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}
	registryUpperHost := DependencyOrigin{ArtifactURL: "https://REGISTRY.NPMJS.ORG/left-pad/-/left-pad-1.3.0.tgz"}
	repo := DependencyOrigin{Repository: "https://github.com/left-pad/left-pad", Revision: "v1.3.0"}
	invalid := DependencyOrigin{ArtifactURL: "file:///home/user/a.tgz"}

	merged := MergeOrigins([]DependencyOrigin{registry}, []DependencyOrigin{registryUpperHost, repo, invalid, {}})
	if len(merged) != 2 {
		t.Fatalf("MergeOrigins = %+v, want the deduplicated pair", merged)
	}
	if merged[0].ArtifactURL != "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz" {
		t.Fatalf("merged[0] = %+v — existing entries come first, normalized", merged[0])
	}
	if merged[1].Repository != "https://github.com/left-pad/left-pad" || merged[1].Revision != "v1.3.0" {
		t.Fatalf("merged[1] = %+v", merged[1])
	}
	if MergeOrigins(nil, []DependencyOrigin{invalid}) != nil {
		t.Fatal("a list of unpublishable origins must merge to nil")
	}
	if MergeOrigins(nil, nil) != nil {
		t.Fatal("empty merge must be nil")
	}
	// Order stability: same inputs, same output.
	again := MergeOrigins([]DependencyOrigin{registry}, []DependencyOrigin{registryUpperHost, repo, invalid, {}})
	for i := range merged {
		if merged[i] != again[i] {
			t.Fatal("MergeOrigins is not deterministic")
		}
	}
}
