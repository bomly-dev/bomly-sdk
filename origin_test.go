package sdk

import (
	"encoding/json"
	"strings"
	"testing"
)

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
func TestPackageOriginNormalized(t *testing.T) {
	cases := []struct {
		name   string
		origin *PackageOrigin
		want   *PackageOrigin
	}{
		{name: "nil"},
		{name: "empty", origin: &PackageOrigin{}},
		{name: "credentialed artifact", origin: &PackageOrigin{ArtifactURL: "https://build:s3cret@nexus.corp/pkg.tgz"}},
		{name: "local repository", origin: &PackageOrigin{Repository: "file:///home/someone/repo"}},
		{name: "revision without a repository", origin: &PackageOrigin{Revision: "9f8e7d6"}},
		{name: "disputed reports nothing", origin: &PackageOrigin{Disputed: true, ArtifactURL: "https://registry.npmjs.org/react/-/react-18.2.0.tgz"}},
		{
			name:   "artifact wins over repository",
			origin: &PackageOrigin{ArtifactURL: "https://registry.npmjs.org/react/-/react-18.2.0.tgz", Repository: "https://github.com/facebook/react"},
			want:   &PackageOrigin{ArtifactURL: "https://registry.npmjs.org/react/-/react-18.2.0.tgz"},
		},
		{
			name:   "query and fragment are stripped from a hand-built repository",
			origin: &PackageOrigin{Repository: "https://github.com/owner/repo?rev=main#abc", Revision: "9f8e7d6"},
			want:   &PackageOrigin{Repository: "https://github.com/owner/repo", Revision: "9f8e7d6"},
		},
		{
			name:   "unusable revision is dropped, repository kept",
			origin: &PackageOrigin{Repository: "https://github.com/owner/repo", Revision: "feature@login"},
			want:   &PackageOrigin{Repository: "https://github.com/owner/repo"},
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
func TestPackageOriginHostCaseIsCanonical(t *testing.T) {
	upper := RepositoryOrigin("https://GitHub.com/Owner/Repo", "aaaabbbbccccddddeeeeffff0000111122223333")
	lower := RepositoryOrigin("https://github.com/Owner/Repo", "aaaabbbbccccddddeeeeffff0000111122223333")

	if upper == nil || lower == nil {
		t.Fatal("both spellings should be publishable")
	}
	if upper.Repository != "https://github.com/Owner/Repo" {
		t.Fatalf("repository = %q, want a lowercased host and an untouched path", upper.Repository)
	}
	if settled := ReconcileOrigin(upper, lower); settled.Empty() {
		t.Fatal("host casing alone must not read as a disagreement")
	}

	// The path is case-sensitive, so these are different locations.
	if settled := ReconcileOrigin(
		ArtifactOrigin("https://example.test/Pkg-1.0.0.tgz"),
		ArtifactOrigin("https://example.test/pkg-1.0.0.tgz"),
	); !settled.Empty() {
		t.Fatalf("origin = %+v, want a disagreement: the paths differ", settled)
	}
}

// An explicit default port names the same origin as no port at all.
func TestPackageOriginDefaultPortIsCanonical(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{name: "https default port", raw: "https://example.test:443/pkg-1.0.0.tgz", want: "https://example.test/pkg-1.0.0.tgz"},
		{name: "http default port", raw: "http://example.test:80/pkg-1.0.0.tgz", want: "http://example.test/pkg-1.0.0.tgz"},
		{name: "a non-default port is part of the location", raw: "https://example.test:8443/pkg-1.0.0.tgz", want: "https://example.test:8443/pkg-1.0.0.tgz"},
		{name: "an IPv6 literal keeps its brackets", raw: "https://[2001:db8::1]:443/pkg-1.0.0.tgz", want: "https://[2001:db8::1]/pkg-1.0.0.tgz"},
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

	if settled := ReconcileOrigin(
		ArtifactOrigin("https://example.test:443/pkg-1.0.0.tgz"),
		ArtifactOrigin("https://example.test/pkg-1.0.0.tgz"),
	); settled.Empty() {
		t.Fatal("a default port alone must not read as a disagreement")
	}
	if settled := ReconcileOrigin(
		ArtifactOrigin("https://example.test:8443/pkg-1.0.0.tgz"),
		ArtifactOrigin("https://example.test/pkg-1.0.0.tgz"),
	); !settled.Empty() {
		t.Fatalf("origin = %+v, want a disagreement: a non-default port is a different location", settled)
	}
}

// Empty and Normalized must answer one question, so a caller that guards on
// Empty can read Normalized without a second nil check.
func TestPackageOriginEmptyAgreesWithNormalized(t *testing.T) {
	origins := []*PackageOrigin{
		nil,
		{},
		{Disputed: true},
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

func TestPackageOriginEmpty(t *testing.T) {
	var nilOrigin *PackageOrigin
	if !nilOrigin.Empty() {
		t.Fatal("nil origin should be empty")
	}
	if !(&PackageOrigin{}).Empty() {
		t.Fatal("zero origin should be empty")
	}
	if !(&PackageOrigin{Disputed: true}).Empty() {
		t.Fatal("a disputed origin names no location, so it is empty")
	}
	if (&PackageOrigin{ArtifactURL: "https://example.test/pkg.tgz"}).Empty() {
		t.Fatal("artifact origin should not be empty")
	}
}

func TestReconcileOrigin(t *testing.T) {
	const (
		artifact = "https://registry.npmjs.org/react/-/react-18.2.0.tgz"
		mirror   = "https://npm.corp/mirror/react/-/react-18.2.0.tgz"
		repo     = "https://github.com/facebook/react"
	)

	cases := []struct {
		name     string
		existing *PackageOrigin
		incoming *PackageOrigin
		want     *PackageOrigin
	}{
		{name: "neither records anything"},
		{name: "records agree", existing: ArtifactOrigin(artifact), incoming: ArtifactOrigin(artifact), want: &PackageOrigin{ArtifactURL: artifact}},
		{name: "absence keeps an origin", existing: ArtifactOrigin(artifact), want: &PackageOrigin{ArtifactURL: artifact}},
		{name: "absence fills a gap", incoming: ArtifactOrigin(artifact), want: &PackageOrigin{ArtifactURL: artifact}},
		{name: "records disagree", existing: ArtifactOrigin(artifact), incoming: ArtifactOrigin(mirror), want: &PackageOrigin{Disputed: true}},
		{name: "different kinds disagree", existing: ArtifactOrigin(artifact), incoming: RepositoryOrigin(repo, ""), want: &PackageOrigin{Disputed: true}},
		{name: "different pins disagree", existing: RepositoryOrigin(repo, "aaaabbbbccccddddeeeeffff0000111122223333"), incoming: RepositoryOrigin(repo, ""), want: &PackageOrigin{Disputed: true}},
		{name: "a disagreement is not lifted by absence", existing: &PackageOrigin{Disputed: true}, want: &PackageOrigin{Disputed: true}},
		{name: "a disagreement is not lifted by agreement", existing: &PackageOrigin{Disputed: true}, incoming: ArtifactOrigin(artifact), want: &PackageOrigin{Disputed: true}},
		{name: "a disputed record poisons a settled one", existing: ArtifactOrigin(artifact), incoming: &PackageOrigin{Disputed: true}, want: &PackageOrigin{Disputed: true}},
		{name: "an unpublishable record is not a disagreement", existing: ArtifactOrigin(artifact), incoming: &PackageOrigin{ArtifactURL: "/Users/someone/pkg.tgz"}, want: &PackageOrigin{ArtifactURL: artifact}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ReconcileOrigin(tc.existing, tc.incoming)
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("reconciled = %+v, want nil", got)
			case tc.want != nil && got == nil:
				t.Fatalf("reconciled = nil, want %+v", tc.want)
			case tc.want != nil && *got != *tc.want:
				t.Fatalf("reconciled = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// Three records claiming A, B, then A must not settle on A.
func TestReconcileOriginDisagreementIsFinal(t *testing.T) {
	const (
		artifact = "https://registry.npmjs.org/react/-/react-18.2.0.tgz"
		mirror   = "https://npm.corp/mirror/react/-/react-18.2.0.tgz"
	)
	settled := ReconcileOrigin(ArtifactOrigin(artifact), ArtifactOrigin(mirror))
	settled = ReconcileOrigin(settled, ArtifactOrigin(artifact))

	if !settled.Empty() {
		t.Fatalf("origin = %+v, want none: the records never agreed", settled)
	}
	if !settled.Disputed {
		t.Fatal("the disagreement must stay recorded, or a later merge revives a disputed value")
	}
}

// A merged graph node carries the reconciled answer rather than whichever
// record was added first.
func TestMergeGraphReconcilesOrigin(t *testing.T) {
	const (
		artifact = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
		mirror   = "https://npm.corp/mirror/lodash/-/lodash-4.17.21.tgz"
	)
	build := func(t *testing.T, url string) *Graph {
		t.Helper()
		g := New()
		node := NewDependencyWithID("lodash@4.17.21", Dependency{
			Coordinates: Coordinates{Name: "lodash", Version: "4.17.21", Ecosystem: EcosystemNPM},
			Origin:      ArtifactOrigin(url),
		})
		if err := g.AddNode(node); err != nil {
			t.Fatal(err)
		}
		return g
	}

	t.Run("disagreement settles to nothing", func(t *testing.T) {
		merged := New()
		if err := MergeGraph(merged, build(t, artifact)); err != nil {
			t.Fatal(err)
		}
		if err := MergeGraph(merged, build(t, mirror)); err != nil {
			t.Fatal(err)
		}
		node, ok := merged.Node("lodash@4.17.21")
		if !ok {
			t.Fatal("expected lodash in the merged graph")
		}
		if got := node.Origin.Normalized(); got != nil {
			t.Fatalf("merged origin = %+v, want none", got)
		}
	})

	t.Run("agreement survives", func(t *testing.T) {
		merged := New()
		if err := MergeGraph(merged, build(t, artifact)); err != nil {
			t.Fatal(err)
		}
		if err := MergeGraph(merged, build(t, artifact)); err != nil {
			t.Fatal(err)
		}
		node, _ := merged.Node("lodash@4.17.21")
		if got := node.Origin.Normalized(); got == nil || got.ArtifactURL != artifact {
			t.Fatalf("merged origin = %+v, want %q", got, artifact)
		}
	})
}

// Cloning a dependency must not leave the copies sharing origin state.
func TestDependencyCloneCopiesOrigin(t *testing.T) {
	dep := NewDependencyWithID("react@18.2.0", Dependency{
		Coordinates: Coordinates{Name: "react", Version: "18.2.0"},
		Origin:      ArtifactOrigin("https://registry.npmjs.org/react/-/react-18.2.0.tgz"),
	})
	clone := dep.Clone()
	clone.Origin.ArtifactURL = "https://npm.corp/mirror/react/-/react-18.2.0.tgz"

	if dep.Origin.ArtifactURL != "https://registry.npmjs.org/react/-/react-18.2.0.tgz" {
		t.Fatalf("mutating a clone changed the original: %+v", dep.Origin)
	}
}

// Origin travels with the package a dependency refers to.
func TestPackageFromDependencyCarriesOrigin(t *testing.T) {
	dep := NewDependencyWithID("react@18.2.0", Dependency{
		Coordinates: Coordinates{Name: "react", Version: "18.2.0", Ecosystem: EcosystemNPM, PURL: "pkg:npm/react@18.2.0"},
		Origin:      ArtifactOrigin("https://registry.npmjs.org/react/-/react-18.2.0.tgz"),
	})
	pkg := PackageFromDependency(dep)
	if pkg.Origin == nil || pkg.Origin.ArtifactURL != "https://registry.npmjs.org/react/-/react-18.2.0.tgz" {
		t.Fatalf("package origin = %+v, want the dependency's", pkg.Origin)
	}
	pkg.Origin.ArtifactURL = "https://npm.corp/mirror/react/-/react-18.2.0.tgz"
	if dep.Origin.ArtifactURL == pkg.Origin.ArtifactURL {
		t.Fatal("package and dependency share origin state")
	}
}

// Registry deduplication settles two records of one package the same way.
func TestPackageMergeFromReconcilesOrigin(t *testing.T) {
	const (
		artifact = "https://registry.npmjs.org/react/-/react-18.2.0.tgz"
		mirror   = "https://npm.corp/mirror/react/-/react-18.2.0.tgz"
	)
	pkg := &Package{Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"}, Origin: ArtifactOrigin(artifact)}
	pkg.MergeFrom(&Package{Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"}, Origin: ArtifactOrigin(mirror)})

	if got := pkg.Origin.Normalized(); got != nil {
		t.Fatalf("merged origin = %+v, want none", got)
	}
}

// The wire contract is additive: an origin-bearing payload round-trips, and a
// payload from a build that predates the field still decodes.
func TestPackageOriginWireRoundTrip(t *testing.T) {
	dep := NewDependencyWithID("react@18.2.0", Dependency{
		Coordinates: Coordinates{Name: "react", Version: "18.2.0"},
		Origin:      RepositoryOrigin("https://github.com/facebook/react", "b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7"),
	})
	raw, err := json.Marshal(dep)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Dependency
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Origin == nil || *decoded.Origin != *dep.Origin {
		t.Fatalf("decoded origin = %+v, want %+v", decoded.Origin, dep.Origin)
	}

	var legacy Dependency
	if err := json.Unmarshal([]byte(`{"id":"react@18.2.0","name":"react","version":"18.2.0"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Origin != nil {
		t.Fatalf("origin = %+v, want nil for a payload that predates the field", legacy.Origin)
	}
	if raw, err := json.Marshal(legacy); err != nil || strings.Contains(string(raw), "origin") {
		t.Fatalf("an absent origin must not be serialized: %s (err %v)", raw, err)
	}
}
