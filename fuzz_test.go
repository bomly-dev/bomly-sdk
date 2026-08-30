package sdk

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk/purlkit"
	"github.com/bomly-dev/bomly-sdk/spdxkit"
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
		if _, err := purlkit.Parse(canonical); err != nil {
			t.Fatalf("canonical package URL does not parse: %q: %v", canonical, err)
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
		`{"nodes":[{"kind":"manifest","id":"manifest:package.json"},{"kind":"module","id":"module:package.json#app","name":"app","declaring_manifest_path":"package.json"},{"kind":"dependency","id":"pkg:npm/left-pad@1.3.0","purl":"pkg:npm/left-pad@1.3.0","name":"left-pad","version":"1.3.0"}],"edges":[{"fromId":"module:package.json#app","toId":"pkg:npm/left-pad@1.3.0"}]}`,
		`{"nodes":[{"id":"a","ecosystem":"npm","name":"left-pad","version":"1.3.0"},{"id":"b","ecosystem":"npm","name":"Left-Pad","version":"1.3.0"}],"edges":[{"fromId":"a","toId":"b"}]}`,
		`{"nodes":[{"kind":"dependency","id":"legacy-opaque","version":"1.0.0"}]}`,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maxFuzzInputSize {
			return
		}
		var graph Graph
		if err := json.Unmarshal(raw, &graph); err != nil {
			// Decode is strict under the typed union: a dependency payload
			// that cannot mint a valid package URL legitimately errors.
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
	graph.WalkNodes(func(node GraphNode) bool {
		if node == nil {
			t.Fatal("graph contains nil node")
		}
		if node.NodeID() == "" {
			t.Fatalf("graph contains node with empty ID: %+v", node)
		}
		return true
	})
	graph.WalkEdges(func(from, to GraphNode) bool {
		if from == nil || to == nil {
			t.Fatalf("graph contains nil edge endpoint: from=%+v to=%+v", from, to)
		}
		if from.NodeID() == "" || to.NodeID() == "" {
			t.Fatalf("graph contains edge with empty endpoint ID: from=%+v to=%+v", from, to)
		}
		return true
	})
}

// FuzzDependencyOrigin drives the origin rule with arbitrary lockfile-derived
// strings: detectors pass raw manifest fields straight through, so whatever a
// repository can put in a lockfile reaches these constructors.
func FuzzDependencyOrigin(f *testing.F) {
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
		// Reading back what was written must reach the same conclusion.
		assertPublishableOrigin(t, repository.Normalized())
		// Normalizing an already-normalized origin must be a fixed point.
		if once, twice := repository.Normalized(), repository.Normalized().Normalized(); !sameOrigin(once, twice) {
			t.Fatalf("normalizing twice changed the origin: %+v then %+v", once, twice)
		}
	})
}

// assertPublishableOrigin fails when an origin carries anything a published
// document must never show.
func assertPublishableOrigin(t *testing.T, origin *DependencyOrigin) {
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
func sameOrigin(left, right *DependencyOrigin) bool {
	switch {
	case left == nil && right == nil:
		return true
	case left == nil || right == nil:
		return false
	default:
		return *left == *right
	}
}

func FuzzCanonicalRepoPath(f *testing.F) {
	for _, seed := range []string{
		"package.json",
		"pkg/sub/package.json",
		"pkg\\sub\\package.json",
		"./pkg/../pkg/package.json",
		"/abs/package.json",
		"C:\\repo\\package.json",
		"../escape/package.json",
		"a#b",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > maxFuzzInputSize {
			return
		}
		canonical, err := CanonicalRepoPath(raw)
		if again, againErr := CanonicalRepoPath(raw); again != canonical || (err == nil) != (againErr == nil) {
			t.Fatalf("CanonicalRepoPath is not deterministic on %q", raw)
		}
		if err != nil {
			return
		}
		// Canonical outputs are idempotent, relative, slash-separated, and
		// free of the reserved bytes the module-ID grammar depends on.
		if again, err := CanonicalRepoPath(canonical); err != nil || again != canonical {
			t.Fatalf("CanonicalRepoPath is not idempotent: %q -> %q (%v)", canonical, again, err)
		}
		if strings.ContainsAny(canonical, "#\\") || strings.HasPrefix(canonical, "/") || strings.HasPrefix(canonical, "../") {
			t.Fatalf("non-canonical output %q", canonical)
		}
	})
}

func FuzzDependencyNodeWire(f *testing.F) {
	for _, seed := range []string{
		`{"id":"pkg:npm/left-pad@1.3.0","purl":"pkg:npm/left-pad@1.3.0","name":"left-pad","version":"1.3.0"}`,
		`{"kind":"dependency","id":"pkg:apk/alpine/musl@1.2.5","purl":"pkg:apk/alpine/musl@1.2.5?arch=x86_64","origins":[{"artifact_url":"https://e.com/a.tgz"}]}`,
		`{"id":"x","version":"1"}`,
		`{"kind":"module","id":"module:package.json#app"}`,
		`{"kind":"bogus","id":"x"}`,
		`null`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maxFuzzInputSize {
			return
		}
		var node DependencyNode
		if err := json.Unmarshal(raw, &node); err != nil {
			return
		}
		// Every accepted payload yields a valid identity, and the codec is a
		// fixed point: re-encoding and re-decoding reproduces the node.
		if node.NodeID() == "" {
			t.Fatalf("decoded dependency node with empty identity from %q", raw)
		}
		encoded, err := json.Marshal(&node)
		if err != nil {
			t.Fatalf("re-encode failed: %v", err)
		}
		var again DependencyNode
		if err := json.Unmarshal(encoded, &again); err != nil {
			t.Fatalf("re-decode failed for %s: %v", encoded, err)
		}
		if again.NodeID() != node.NodeID() {
			t.Fatalf("identity not stable across the codec: %q -> %q", node.NodeID(), again.NodeID())
		}
	})
}

// FuzzDigestAlgorithm drives the algorithm registry with arbitrary strings:
// algorithm names arrive from ingested SBOM documents and plugin payloads, so
// whatever a document can spell reaches this parser.
func FuzzDigestAlgorithm(f *testing.F) {
	for _, seed := range []string{
		"sha256", "SHA-256", "SHA256", "sha3-512", "BLAKE2b-256", "ADLER32",
		"", "   ", "crc32", "sha-------256", "SHA_256", "s.h.a.2.5.6",
		strings.Repeat("sha256", 200), "\x00sha256", "sha256\n",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, value string) {
		algorithm, err := ParseDigestAlgorithm(value)
		if err != nil {
			if algorithm != "" {
				t.Fatalf("ParseDigestAlgorithm(%q) returned %q alongside an error", value, algorithm)
			}
			return
		}
		// A parsed algorithm is registered, and re-parsing its canonical token
		// is a fixed point -- otherwise a value would change identity every
		// time it crossed the wire.
		if !algorithm.Valid() {
			t.Fatalf("ParseDigestAlgorithm(%q) returned unregistered %q", value, algorithm)
		}
		again, err := ParseDigestAlgorithm(string(algorithm))
		if err != nil || again != algorithm {
			t.Fatalf("re-parsing %q gave %q, %v", algorithm, again, err)
		}
		// A registered algorithm names at least one format, or it could never
		// be published and has no business in the registry.
		if algorithm.SPDXName() == "" && algorithm.CycloneDXName() == "" {
			t.Fatalf("%q has no format projection", algorithm)
		}
	})
}

// FuzzContact drives the contact gate with arbitrary supplier strings, which
// arrive verbatim from ingested SBOM documents.
func FuzzContact(f *testing.F) {
	for _, seed := range []string{
		"Organization: Acme Inc", "Person: Jane Doe", "NOASSERTION",
		"Organization: Acme Inc (info@acme.com)", "Organization:", "Acme Inc",
		"", "person:", "PERSON: (a@b.c)", "Organization: a\nb", "Organization: (",
		strings.Repeat("Person: a", 100), "Organization: \x00",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, value string) {
		contact, ok := ParseSPDXContact(value)
		if !ok {
			return
		}
		assertPublishableContact(t, contact)
		// Normalizing an already-normalized contact is a fixed point.
		once, ok := contact.Normalized()
		if !ok {
			t.Fatalf("a parsed contact %+v failed its own gate", contact)
		}
		twice, ok := once.Normalized()
		if !ok || twice != once {
			t.Fatalf("normalizing twice changed the contact: %+v then %+v", once, twice)
		}
		// Rendering and re-reading must reach the same value, or a contact
		// would drift every time it round-tripped through SPDX.
		if rendered := contact.SPDXString(); rendered != "" {
			reparsed, ok := ParseSPDXContact(rendered)
			if !ok || reparsed != contact {
				t.Fatalf("round trip of %+v through %q gave %+v (ok=%v)", contact, rendered, reparsed, ok)
			}
		}
	})
}

// assertPublishableContact fails when a contact carries anything a published
// document must never show.
func assertPublishableContact(t *testing.T, contact Contact) {
	t.Helper()
	for _, r := range contact.Name {
		if r < ' ' || r == 0x7f {
			t.Fatalf("contact name %q carries a control character", contact.Name)
		}
	}
	if len(contact.Name) > maxContactNameLength {
		t.Fatalf("contact name is %d bytes, over the limit", len(contact.Name))
	}
	// An email address is deliberately not carried, wherever the document put
	// it; see Contact's docs.
	if strings.Contains(contact.Name, "@") {
		t.Fatalf("contact name %q retains an address-shaped token", contact.Name)
	}
	if contact.URL != "" {
		if _, ok := NormalizeURL(contact.URL, URLFormReference); !ok {
			t.Fatalf("contact URL %q would be rejected on read", contact.URL)
		}
	}
}

// FuzzPackageLicense drives the license gate with arbitrary claims. License
// values and extracted text arrive from lockfiles, registry APIs, and ingested
// SBOM documents, all untrusted.
func FuzzPackageLicense(f *testing.F) {
	for _, seed := range []struct{ value, expression, text, licenseType string }{
		{"MIT", "MIT", "", "declared"},
		{"MIT", "MIT", "", "concluded"},
		{"Custom", "LicenseRef-Acme-Commercial", "Custom terms.", ""},
		{"Custom", "LicenseRef-bomly-00000000000000000000000000000000", "Custom terms.", ""},
		{"Custom", `LicenseRef-Acme Commercial "v2"`, "Custom terms.", ""},
		{"Custom", "LicenseRef-Acme", "", "declared"},
		{"", "", "Only text.", ""},
		{"", "", "", ""},
		{"MIT", "MIT", "", "invented"},
	} {
		f.Add(seed.value, seed.expression, seed.text, seed.licenseType)
	}

	f.Fuzz(func(t *testing.T, value, expression, text, licenseType string) {
		license := PackageLicense{
			Value:          value,
			SPDXExpression: expression,
			ExtractedText:  text,
			Type:           LicenseType(licenseType),
		}
		normalized, ok := license.Normalized()
		if !ok {
			if normalized != (PackageLicense{}) {
				t.Fatalf("a rejected license returned %+v, want the zero value", normalized)
			}
			return
		}
		// Provenance is a closed vocabulary: an unrecognized one must never
		// survive as a published claim.
		if _, err := ParseLicenseType(string(normalized.Type)); err != nil {
			t.Fatalf("normalized license carries unrecognized provenance %q", normalized.Type)
		}
		// A license reference must be well formed and must have its text, or
		// the document citing it would not validate.
		if strings.HasPrefix(normalized.SPDXExpression, spdxkit.LicenseRefPrefix) {
			if !spdxkit.ValidLicenseRef(normalized.SPDXExpression) {
				t.Fatalf("normalized license carries malformed reference %q", normalized.SPDXExpression)
			}
			if strings.TrimSpace(normalized.ExtractedText) == "" {
				t.Fatalf("reference %q survived without its text", normalized.SPDXExpression)
			}
		}
		// Normalizing twice is a fixed point.
		twice, ok := normalized.Normalized()
		if !ok || twice != normalized {
			t.Fatalf("normalizing twice changed the license: %+v then %+v", normalized, twice)
		}
	})
}

// FuzzNormalizeURL drives all three published-URL forms with arbitrary input.
func FuzzNormalizeURL(f *testing.F) {
	for _, seed := range []string{
		"https://example.test", "https://example.test/docs?page=1#anchor",
		"https://user:pw@example.test/", "file:///etc/passwd", "/local/path",
		"git@github.test:owner/repo.git", "https://", "https://:8080/x",
		"http://0#0", "%./0", "https://example.test/a%2Fb", "https://EXAMPLE.test:443/x",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		for _, form := range []URLForm{URLFormArtifact, URLFormRepository, URLFormReference} {
			normalized, ok := NormalizeURL(raw, form)
			if !ok {
				if normalized != "" {
					t.Fatalf("form %v rejected %q but returned %q", form, raw, normalized)
				}
				continue
			}
			assertPublishableURL(t, form, normalized)
			// Reading back what was written must reach the same conclusion,
			// and must be a fixed point: a value that changed on every pass
			// would drift each time it crossed the wire.
			again, ok := NormalizeURL(normalized, form)
			if !ok || again != normalized {
				t.Fatalf("form %v: re-normalizing %q gave %q (ok=%v)", form, normalized, again, ok)
			}
		}
	})
}

// assertPublishableURL fails when a normalized URL carries anything a
// published document must never show.
func assertPublishableURL(t *testing.T, form URLForm, raw string) {
	t.Helper()
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
	switch form {
	case URLFormArtifact:
		if parsed.RawQuery != "" || parsed.ForceQuery {
			t.Fatalf("artifact URL %q carries a query", raw)
		}
		fallthrough
	case URLFormRepository:
		if parsed.RawQuery != "" || parsed.ForceQuery {
			t.Fatalf("repository URL %q carries a query", raw)
		}
		if strings.Trim(parsed.Path, "/") == "" {
			t.Fatalf("origin URL %q names a host root, not a package", raw)
		}
		if parsed.Fragment != "" {
			t.Fatalf("origin URL %q carries a fragment", raw)
		}
	}
}
