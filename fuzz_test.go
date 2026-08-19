package sdk

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

const maxFuzzInputSize = 1 << 20

func FuzzCanonicalizePackageURL(f *testing.F) {
	for _, seed := range []string{
		"pkg:npm/%40scope/name@1.0.0",
		"pkg:golang/github.com/bomly-dev/bomly-cli@v0.1.0",
		"pkg:pypi/requests@2.31.0",
		"not a package url",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > maxFuzzInputSize {
			return
		}
		canonical := CanonicalizePackageURL(raw)
		if canonical == "" {
			return
		}
		if reparsed := ParsePackageURL(canonical); reparsed == nil {
			t.Fatalf("canonical package URL does not parse: %q", canonical)
		}
		if again := CanonicalizePackageURL(canonical); again != canonical {
			t.Fatalf("package URL canonicalization is not stable: %q then %q", canonical, again)
		}
	})
}

func FuzzGraphJSON(f *testing.F) {
	for _, seed := range []string{
		`null`,
		`{"nodes":[{"id":"app","name":"app","version":"1.0.0"},{"id":"dep","name":"dep","version":"2.0.0"}],"edges":[{"fromId":"app","toId":"dep"}]}`,
		`{"nodes":[{"id":"pkg:npm/react@18.2.0","purl":"pkg:npm/react@18.2.0","name":"react","version":"18.2.0"}]}`,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maxFuzzInputSize {
			return
		}
		var graph Graph
		if err := json.Unmarshal(raw, &graph); err != nil {
			return
		}
		requireFuzzGraphValid(t, &graph)
		encoded, err := json.Marshal(&graph)
		if err != nil {
			t.Fatalf("marshal graph after successful unmarshal: %v", err)
		}
		var roundTrip Graph
		if err := json.Unmarshal(encoded, &roundTrip); err != nil {
			t.Fatalf("round-trip graph JSON does not unmarshal: %v", err)
		}
		requireFuzzGraphValid(t, &roundTrip)
		requireStableJSON(t, "graph", &graph, &roundTrip)
	})
}

func FuzzPackageRegistryJSON(f *testing.F) {
	for _, seed := range []string{
		`null`,
		`{"pkg:npm/react@18.2.0":{"name":"react","version":"18.2.0","purl":"pkg:npm/react@18.2.0"}}`,
		`{"pkg:golang/github.com/bomly-dev/bomly-cli@v0.1.0":{"name":"github.com/bomly-dev/bomly-cli","version":"v0.1.0"}}`,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maxFuzzInputSize {
			return
		}
		var registry PackageRegistry
		if err := json.Unmarshal(raw, &registry); err != nil {
			return
		}
		requireFuzzRegistryValid(t, &registry)
		encoded, err := json.Marshal(&registry)
		if err != nil {
			t.Fatalf("marshal registry after successful unmarshal: %v", err)
		}
		var roundTrip PackageRegistry
		if err := json.Unmarshal(encoded, &roundTrip); err != nil {
			t.Fatalf("round-trip registry JSON does not unmarshal: %v", err)
		}
		requireFuzzRegistryValid(t, &roundTrip)
		requireStableJSON(t, "package registry", &registry, &roundTrip)
	})
}

func requireStableJSON(t *testing.T, label string, before any, after any) {
	t.Helper()
	beforeJSON, err := json.Marshal(before)
	if err != nil {
		t.Fatalf("marshal %s before comparison: %v", label, err)
	}
	afterJSON, err := json.Marshal(after)
	if err != nil {
		t.Fatalf("marshal %s after comparison: %v", label, err)
	}
	if string(afterJSON) != string(beforeJSON) {
		t.Fatalf("%s changed after round trip:\nbefore: %s\nafter:  %s", label, beforeJSON, afterJSON)
	}
}

func requireFuzzRegistryValid(t *testing.T, registry *PackageRegistry) {
	t.Helper()
	for _, pkg := range registry.All() {
		if pkg == nil {
			t.Fatal("registry contains nil package after successful unmarshal")
		}
		if pkg.PURL == "" {
			t.Fatalf("registry contains package with empty PURL: %+v", pkg)
		}
	}
}

func requireFuzzGraphValid(t *testing.T, graph *Graph) {
	t.Helper()
	if graph == nil {
		t.Fatal("nil graph")
	}
	graph.WalkNodes(func(node *Dependency) bool {
		if node == nil {
			t.Fatal("graph contains nil node")
		}
		if node.ID == "" {
			t.Fatalf("graph contains node with empty ID: %+v", node)
		}
		return true
	})
	graph.WalkEdges(func(from, to *Dependency) bool {
		if from == nil || to == nil {
			t.Fatalf("graph contains nil edge endpoint: from=%+v to=%+v", from, to)
		}
		if from.ID == "" || to.ID == "" {
			t.Fatalf("graph contains edge with empty endpoint ID: from=%+v to=%+v", from, to)
		}
		return true
	})
}

// FuzzPackageOrigin drives the origin rule with arbitrary lockfile-derived
// strings: detectors pass raw manifest fields straight through, so whatever a
// repository can put in a lockfile reaches these constructors.
func FuzzPackageOrigin(f *testing.F) {
	f.Add("https://registry.npmjs.org/react/-/react-18.2.0.tgz", "")
	f.Add("https://github.com/owner/repo.git", "9f8e7d6c5b4a3928176554433221100ffeeddcc0")
	f.Add("https://github.com/example/helper?rev=main#abc123", "v1.2.3")
	f.Add("https://user:s3cret@nexus.corp/repo/pkg.tgz", "main")
	f.Add("git+ssh://git@github.com/owner/repo.git#9f8e7d6", "9f8e7d6")
	f.Add("file:///home/someone/wheels/pkg.whl", "")
	f.Add("/Users/someone/src/project", "")
	f.Add("http://0#0", "0")
	f.Add("http://0/0#\x02", "\x02")
	f.Add("%./0", "%")
	f.Add("https://", "")
	f.Add("https://:8080/pkg.tgz", "")
	f.Add("https://registry.example.test/", "")

	f.Fuzz(func(t *testing.T, rawURL, revision string) {
		artifact, repository := ArtifactOrigin(rawURL), RepositoryOrigin(rawURL, revision)
		assertPublishableOrigin(t, artifact)
		assertPublishableOrigin(t, repository)
		// Reading back what was written must reach the same conclusion, and
		// reconciling a record with itself must not change it.
		assertPublishableOrigin(t, repository.Normalized())
		// Normalizing an already-normalized origin must be a fixed point.
		if once, twice := repository.Normalized(), repository.Normalized().Normalized(); !sameOrigin(once, twice) {
			t.Fatalf("normalizing twice changed the origin: %+v then %+v", once, twice)
		}
		if settled, again := ReconcileOrigin(repository, repository), repository.Normalized(); !sameOrigin(settled, again) {
			t.Fatalf("reconciling a record with itself changed it: %+v then %+v", again, settled)
		}
		// A disagreement is recorded rather than resolved, whatever the inputs.
		normalized := artifact.Normalized()
		if other := ArtifactOrigin("https://registry.example.test/other/pkg-1.0.0.tgz"); normalized != nil && normalized.ArtifactURL != other.ArtifactURL {
			if settled := ReconcileOrigin(artifact, other); !settled.Empty() {
				t.Fatalf("two different origins settled on %+v", settled)
			}
		}
	})
}

// assertPublishableOrigin fails when an origin carries anything a published
// document must never show.
func assertPublishableOrigin(t *testing.T, origin *PackageOrigin) {
	t.Helper()
	normalized := origin.Normalized()
	if normalized == nil {
		return
	}
	if normalized.ArtifactURL != "" && normalized.Repository != "" {
		t.Fatalf("origin names two locations at once: %+v", normalized)
	}
	if normalized.Revision != "" && normalized.Repository == "" {
		t.Fatalf("revision %q recorded without a repository", normalized.Revision)
	}
	for _, raw := range []string{normalized.ArtifactURL, normalized.Repository} {
		if raw == "" {
			continue
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("published URL %q does not parse: %v", raw, err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			t.Fatalf("published URL %q is not a web location", raw)
		}
		if parsed.Hostname() == "" {
			t.Fatalf("published URL %q has no host", raw)
		}
		if parsed.User != nil {
			t.Fatalf("published URL %q carries credentials", raw)
		}
		if parsed.Fragment != "" {
			t.Fatalf("published URL %q carries a fragment", raw)
		}
		if strings.Trim(parsed.Path, "/") == "" {
			t.Fatalf("published URL %q names a host root, not a package", raw)
		}
	}
	if normalized.Repository != "" {
		parsed, _ := url.Parse(normalized.Repository)
		if parsed.RawQuery != "" || parsed.ForceQuery {
			t.Fatalf("repository %q carries a query", normalized.Repository)
		}
	}
	if !isValidOriginRevision(normalized.Revision) && normalized.Revision != "" {
		t.Fatalf("revision %q would break a locator grammar", normalized.Revision)
	}
}

// sameOrigin compares two origins that may be nil.
func sameOrigin(left, right *PackageOrigin) bool {
	switch {
	case left == nil && right == nil:
		return true
	case left == nil || right == nil:
		return false
	default:
		return *left == *right
	}
}
