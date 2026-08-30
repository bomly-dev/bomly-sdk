package sdk

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk/spdxkit"
)

// --- digest algorithm registry -------------------------------------------

// TestDigestAlgorithmSquashKeysDoNotCollide guards the squashed alias index.
// Dropping separators is what lets "SHA-256", "SHA256", and "sha256" resolve
// to one value without listing every variant, and it is only sound while no
// two registry rows squash to the same key. A future row that collided would
// silently resolve one algorithm's spelling to another algorithm.
func TestDigestAlgorithmSquashKeysDoNotCollide(t *testing.T) {
	owner := make(map[string]DigestAlgorithm, len(digestAlgorithmProfiles)*3)
	for _, profile := range digestAlgorithmProfiles {
		for _, spelling := range []string{string(profile.canonical), profile.spdx, profile.cycloneDX} {
			squashed := squashDigestAlgorithm(spelling)
			if squashed == "" {
				continue
			}
			if existing, found := owner[squashed]; found && existing != profile.canonical {
				t.Fatalf("spelling %q squashes to %q, claimed by both %q and %q", spelling, squashed, existing, profile.canonical)
			}
			owner[squashed] = profile.canonical
		}
	}
}

func TestParseDigestAlgorithmAcceptsEveryFormatSpelling(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  DigestAlgorithm
	}{
		{"sha256", DigestAlgorithmSHA256},
		{"SHA256", DigestAlgorithmSHA256},  // SPDX
		{"SHA-256", DigestAlgorithmSHA256}, // CycloneDX
		{" sha-256 ", DigestAlgorithmSHA256},
		{"SHA3-512", DigestAlgorithmSHA3512},
		{"sha3512", DigestAlgorithmSHA3512},
		{"BLAKE2b-256", DigestAlgorithmBLAKE2b256},
		{"blake2b256", DigestAlgorithmBLAKE2b256},
		{"ADLER32", DigestAlgorithmADLER32},
	} {
		got, err := ParseDigestAlgorithm(tc.input)
		if err != nil {
			t.Fatalf("ParseDigestAlgorithm(%q): unexpected error %v", tc.input, err)
		}
		if got != tc.want {
			t.Fatalf("ParseDigestAlgorithm(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
	for _, input := range []string{"", "   ", "crc32", "sha257", "rot13"} {
		if got, err := ParseDigestAlgorithm(input); err == nil {
			t.Fatalf("ParseDigestAlgorithm(%q) = %q, want an error", input, got)
		}
	}
}

// TestDigestAlgorithmFormatProjections pins that an algorithm one format does
// not define reports no spelling there. A caller treats "" as "omit this
// digest"; returning the canonical token instead would emit a value that
// fails the format's own schema validation.
func TestDigestAlgorithmFormatProjections(t *testing.T) {
	if got := DigestAlgorithmSHA256.SPDXName(); got != "SHA256" {
		t.Fatalf("SHA256 SPDX name = %q, want %q", got, "SHA256")
	}
	if got := DigestAlgorithmSHA256.CycloneDXName(); got != "SHA-256" {
		t.Fatalf("SHA256 CycloneDX name = %q, want %q", got, "SHA-256")
	}
	// SPDX defines these; CycloneDX 1.5/1.6 does not.
	for _, algorithm := range []DigestAlgorithm{
		DigestAlgorithmMD2, DigestAlgorithmMD4, DigestAlgorithmMD6,
		DigestAlgorithmSHA224, DigestAlgorithmADLER32,
	} {
		if got := algorithm.SPDXName(); got == "" {
			t.Fatalf("%q has no SPDX spelling, but the registry lists it as SPDX-defined", algorithm)
		}
		if got := algorithm.CycloneDXName(); got != "" {
			t.Fatalf("%q reports CycloneDX spelling %q, but CycloneDX does not define it", algorithm, got)
		}
	}
	if got := DigestAlgorithm("not-registered").SPDXName(); got != "" {
		t.Fatalf("unregistered algorithm reported SPDX spelling %q", got)
	}
}

// TestDigestWireNormalizesForeignSpellings pins that a producer writing a
// format's own spelling is understood. Without the codec the value would be
// stored as an algorithm no comparison matches, and every digest from a
// CycloneDX-shaped producer would silently fail to deduplicate.
func TestDigestWireNormalizesForeignSpellings(t *testing.T) {
	var digest Digest
	if err := json.Unmarshal([]byte(`{"algorithm":"SHA-256","value":"abc123"}`), &digest); err != nil {
		t.Fatalf("decode digest: %v", err)
	}
	if digest.Algorithm != DigestAlgorithmSHA256 {
		t.Fatalf("decoded algorithm = %q, want %q", digest.Algorithm, DigestAlgorithmSHA256)
	}
	encoded, err := json.Marshal(digest)
	if err != nil {
		t.Fatalf("encode digest: %v", err)
	}
	if !strings.Contains(string(encoded), `"algorithm":"sha256"`) {
		t.Fatalf("encoded digest = %s, want the canonical algorithm token", encoded)
	}
}

func TestDigestWireDropsUnpublishableValues(t *testing.T) {
	for _, payload := range []string{
		`{"algorithm":"crc32","value":"abc"}`,
		`{"algorithm":"sha256","value":""}`,
		`{"algorithm":"sha256","value":"abc def"}`,
		"{\"algorithm\":\"sha256\",\"value\":\"abc\\u0000def\"}",
	} {
		var digest Digest
		if err := json.Unmarshal([]byte(payload), &digest); err != nil {
			t.Fatalf("decode %s: %v", payload, err)
		}
		if digest != (Digest{}) {
			t.Fatalf("payload %s decoded to %+v, want the zero digest", payload, digest)
		}
	}
}

// --- contacts -------------------------------------------------------------

func TestParseSPDXContact(t *testing.T) {
	for _, tc := range []struct {
		input    string
		wantKind ContactKind
		wantName string
		wantOK   bool
	}{
		{"Organization: Acme Inc", ContactKindOrganization, "Acme Inc", true},
		{"Person: Jane Doe", ContactKindPerson, "Jane Doe", true},
		{"NOASSERTION", ContactKindNoAssertion, "", true},
		{"noassertion", ContactKindNoAssertion, "", true},
		{"organization: Acme Inc", ContactKindOrganization, "Acme Inc", true},
		// The email parenthetical is stripped; see Contact's documentation.
		{"Organization: Acme Inc (info@acme.com)", ContactKindOrganization, "Acme Inc", true},
		{"Person: Jane Doe (jane@example.com)", ContactKindPerson, "Jane Doe", true},
		// SPDX requires a kind prefix. Guessing one would publish a claim the
		// document did not make.
		{"Acme Inc", ContactKindUnknown, "", false},
		{"", ContactKindUnknown, "", false},
		{"Organization:", ContactKindUnknown, "", false},
		{"Organization: (only@email.com)", ContactKindUnknown, "", false},
	} {
		got, ok := ParseSPDXContact(tc.input)
		if ok != tc.wantOK {
			t.Fatalf("ParseSPDXContact(%q) ok = %v, want %v (got %+v)", tc.input, ok, tc.wantOK, got)
		}
		if !ok {
			continue
		}
		if got.Kind != tc.wantKind || got.Name != tc.wantName {
			t.Fatalf("ParseSPDXContact(%q) = %+v, want kind %q name %q", tc.input, got, tc.wantKind, tc.wantName)
		}
	}
}

// TestContactCarriesNoEmailAddress pins the privacy decision: ADR-0037 defers
// supplier-contact privacy, so an address in an ingested document must not be
// retained anywhere on the value -- not in the name, not in a spare field.
func TestContactCarriesNoEmailAddress(t *testing.T) {
	contact, ok := ParseSPDXContact("Organization: Acme Inc (secrets@acme.com)")
	if !ok {
		t.Fatal("ParseSPDXContact rejected a valid supplier")
	}
	encoded, err := json.Marshal(contact)
	if err != nil {
		t.Fatalf("encode contact: %v", err)
	}
	if strings.Contains(string(encoded), "@") {
		t.Fatalf("encoded contact %s retains an email address", encoded)
	}
}

func TestContactSPDXRoundTrip(t *testing.T) {
	for _, input := range []string{"Organization: Acme Inc", "Person: Jane Doe", "NOASSERTION"} {
		contact, ok := ParseSPDXContact(input)
		if !ok {
			t.Fatalf("ParseSPDXContact(%q) rejected a valid value", input)
		}
		if got := contact.SPDXString(); got != input {
			t.Fatalf("round trip of %q produced %q", input, got)
		}
	}
	// A contact of unknown kind has no valid SPDX rendering.
	unknown := Contact{Name: "Acme Inc"}
	if got := unknown.SPDXString(); got != "" {
		t.Fatalf("unknown-kind contact rendered as %q, want the empty omit signal", got)
	}
}

func TestContactNormalizedGates(t *testing.T) {
	// A control character would corrupt SPDX's line-oriented tag form.
	if _, ok := (Contact{Kind: ContactKindOrganization, Name: "Acme\nInc"}).Normalized(); ok {
		t.Fatal("a name carrying a newline was accepted")
	}
	// URLs are held to the reference form: credentials are rejected, a bare
	// host is fine.
	withCreds := Contact{Kind: ContactKindOrganization, Name: "Acme", URL: "https://user:pw@acme.test/"}
	normalized, ok := withCreds.Normalized()
	if !ok {
		t.Fatal("a valid contact was rejected for its URL")
	}
	if normalized.URL != "" {
		t.Fatalf("credentials survived normalization: %q", normalized.URL)
	}
	bareHost := Contact{Kind: ContactKindOrganization, Name: "Acme", URL: "https://acme.test"}
	if normalized, ok = bareHost.Normalized(); !ok || normalized.URL == "" {
		t.Fatalf("a bare-host URL was dropped: %+v ok=%v", normalized, ok)
	}
}

// --- licenses -------------------------------------------------------------

// TestMergeLicensesKeepsDeclaredAndConcludedApart pins the reason the type
// gained provenance at all. Deduplicating on the expression alone would
// collapse "the package says MIT" and "our analysis concluded MIT" into one
// claim and lose which of them was actually made.
func TestMergeLicensesKeepsDeclaredAndConcludedApart(t *testing.T) {
	merged := MergeLicenses(
		[]PackageLicense{{Value: "MIT", SPDXExpression: "MIT", Type: LicenseTypeDeclared}},
		[]PackageLicense{
			{Value: "MIT", SPDXExpression: "MIT", Type: LicenseTypeConcluded},
			{Value: "MIT", SPDXExpression: "MIT", Type: LicenseTypeDeclared},
		},
	)
	if len(merged) != 2 {
		t.Fatalf("merged licenses = %+v, want the declared and concluded claims and no duplicate", merged)
	}
	kinds := map[LicenseType]int{}
	for _, license := range merged {
		kinds[license.Type]++
	}
	if kinds[LicenseTypeDeclared] != 1 || kinds[LicenseTypeConcluded] != 1 {
		t.Fatalf("merged licenses = %+v, want exactly one of each provenance", merged)
	}
}

func TestPackageLicenseNormalizedLicenseRefRules(t *testing.T) {
	text := "Custom terms, all rights reserved."
	minted := spdxkit.MintLicenseRef(text).RefID

	t.Run("bomly reference is re-minted from its text", func(t *testing.T) {
		// The text is authoritative, so a reference that disagrees is
		// repaired rather than trusted: publishing it would cite the wrong
		// license.
		license := PackageLicense{
			SPDXExpression: spdxkit.BomlyLicenseRefPrefix + "0000000000000000000000000000000f",
			ExtractedText:  text,
		}
		normalized, ok := license.Normalized()
		if !ok {
			t.Fatal("a license with text was rejected")
		}
		if normalized.SPDXExpression != minted {
			t.Fatalf("expression = %q, want the reference the text mints (%q)", normalized.SPDXExpression, minted)
		}
	})

	t.Run("a source document's own reference is preserved", func(t *testing.T) {
		// Re-minting here would rename an identifier the source defined, so
		// re-exporting that document would no longer reproduce it.
		license := PackageLicense{SPDXExpression: "LicenseRef-Acme-Commercial", ExtractedText: text}
		normalized, ok := license.Normalized()
		if !ok {
			t.Fatal("a license with text was rejected")
		}
		if normalized.SPDXExpression != "LicenseRef-Acme-Commercial" {
			t.Fatalf("expression = %q, want the source's own reference", normalized.SPDXExpression)
		}
	})

	t.Run("a malformed reference is re-minted", func(t *testing.T) {
		// A reference carrying a space or a quote would corrupt the emitted
		// expression, so it cannot be written verbatim.
		license := PackageLicense{SPDXExpression: `LicenseRef-Acme Commercial "v2"`, ExtractedText: text}
		normalized, ok := license.Normalized()
		if !ok {
			t.Fatal("a license with text was rejected")
		}
		if normalized.SPDXExpression != minted {
			t.Fatalf("expression = %q, want the minted reference", normalized.SPDXExpression)
		}
	})

	t.Run("a reference without text cannot be cited", func(t *testing.T) {
		license := PackageLicense{Value: "Custom", SPDXExpression: "LicenseRef-Acme-Commercial"}
		normalized, ok := license.Normalized()
		if !ok {
			t.Fatal("a license with a stated value was rejected")
		}
		if normalized.SPDXExpression != "" {
			t.Fatalf("expression = %q, want it dropped: the citation would dangle", normalized.SPDXExpression)
		}
		if normalized.Value != "Custom" {
			t.Fatalf("value = %q, want the stated value to survive", normalized.Value)
		}
	})

	t.Run("text without a reference mints one", func(t *testing.T) {
		license := PackageLicense{Value: "Custom", ExtractedText: text}
		normalized, ok := license.Normalized()
		if !ok {
			t.Fatal("a license with text was rejected")
		}
		if normalized.SPDXExpression != minted {
			t.Fatalf("expression = %q, want text to mint its citation (%q)", normalized.SPDXExpression, minted)
		}
	})
}

func TestPackageLicenseWireGates(t *testing.T) {
	var license PackageLicense
	if err := json.Unmarshal([]byte(`{"value":"MIT","type":"invented"}`), &license); err != nil {
		t.Fatalf("decode license: %v", err)
	}
	if license.Type != "" {
		t.Fatalf("decoded provenance = %q, want it dropped to unknown", license.Type)
	}
	if license.Value != "MIT" {
		t.Fatalf("decoded value = %q, want the stated value to survive", license.Value)
	}
	// A record with nothing publishable decodes to the zero value.
	if err := json.Unmarshal([]byte(`{"type":"declared"}`), &license); err != nil {
		t.Fatalf("decode license: %v", err)
	}
	if license != (PackageLicense{}) {
		t.Fatalf("empty claim decoded to %+v, want the zero value", license)
	}
}

// --- URL forms ------------------------------------------------------------

// TestURLFormReferenceAcceptsCitations pins the reason the third form exists:
// a homepage is legitimately a bare host with a query, both of which the
// artifact and repository forms reject or strip.
func TestURLFormReferenceAcceptsCitations(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"https://example.test", "https://example.test"},
		{"https://example.test/", "https://example.test/"},
		{"https://example.test/docs?page=install", "https://example.test/docs?page=install"},
		{"https://example.test/advisories#GHSA-1234", "https://example.test/advisories#GHSA-1234"},
	} {
		got, ok := NormalizeURL(tc.input, URLFormReference)
		if !ok {
			t.Fatalf("NormalizeURL(%q, reference) was rejected", tc.input)
		}
		if got != tc.want {
			t.Fatalf("NormalizeURL(%q, reference) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestURLFormsKeepTheirOwnRules pins that adding the reference form did not
// loosen the other two.
func TestURLFormsKeepTheirOwnRules(t *testing.T) {
	// The artifact form still rejects a query: it marks a signed link.
	if got, ok := NormalizeURL("https://cdn.test/pkg.tgz?token=abc", URLFormArtifact); ok {
		t.Fatalf("artifact form accepted a tokenized link: %q", got)
	}
	// The repository form still drops one.
	got, ok := NormalizeURL("https://github.test/owner/repo?rev=main", URLFormRepository)
	if !ok || got != "https://github.test/owner/repo" {
		t.Fatalf("repository form = %q ok=%v, want the query dropped", got, ok)
	}
	// A host root is still not an artifact or a repository.
	for _, form := range []URLForm{URLFormArtifact, URLFormRepository} {
		if got, ok := NormalizeURL("https://registry.test/", form); ok {
			t.Fatalf("form %v accepted a host root: %q", form, got)
		}
	}
	// Credentials are rejected by every form, the new one included.
	for _, form := range []URLForm{URLFormArtifact, URLFormRepository, URLFormReference} {
		if got, ok := NormalizeURL("https://user:pw@example.test/pkg", form); ok {
			t.Fatalf("form %v accepted embedded credentials: %q", form, got)
		}
	}
	// So are non-web schemes.
	for _, form := range []URLForm{URLFormArtifact, URLFormRepository, URLFormReference} {
		for _, raw := range []string{"file:///etc/passwd", "git@github.test:owner/repo.git", "/local/path"} {
			if got, ok := NormalizeURL(raw, form); ok {
				t.Fatalf("form %v accepted %q: %q", form, raw, got)
			}
		}
	}
}

// TestNormalizeOriginURLStillSelectsTheOriginForms pins the compatibility
// wrapper: detectors and plugins call it by name, and swapping which form the
// boolean selects would silently change every recorded origin.
func TestNormalizeOriginURLStillSelectsTheOriginForms(t *testing.T) {
	if _, ok := NormalizeOriginURL("https://cdn.test/pkg.tgz?token=abc", false); ok {
		t.Fatal("NormalizeOriginURL(false) accepted a query; it must select the artifact form")
	}
	got, ok := NormalizeOriginURL("https://github.test/owner/repo?rev=main", true)
	if !ok || got != "https://github.test/owner/repo" {
		t.Fatalf("NormalizeOriginURL(true) = %q ok=%v; it must select the repository form", got, ok)
	}
}

// --- description and homepage gates ---------------------------------------

func TestNormalizeDescription(t *testing.T) {
	if got := NormalizeDescription("  A tidy package.  "); got != "A tidy package." {
		t.Fatalf("NormalizeDescription trimmed to %q", got)
	}
	// Line structure is part of a legitimate description.
	if got := NormalizeDescription("line one\nline two\ttabbed"); got != "line one\nline two\ttabbed" {
		t.Fatalf("NormalizeDescription damaged line structure: %q", got)
	}
	// Other control characters came from a malformed document.
	if got := NormalizeDescription("clean\x00text\x07"); got != "cleantext" {
		t.Fatalf("NormalizeDescription = %q, want the control characters dropped", got)
	}
	// Over-long input yields nothing rather than a truncation presented as a
	// complete description.
	if got := NormalizeDescription(strings.Repeat("a", maxDescriptionLength+1)); got != "" {
		t.Fatalf("an over-long description survived as %d bytes", len(got))
	}
}

func TestNormalizeHomepageUsesTheReferenceForm(t *testing.T) {
	if got := NormalizeHomepage("https://example.test"); got != "https://example.test" {
		t.Fatalf("NormalizeHomepage rejected a bare-host project page: %q", got)
	}
	if got := NormalizeHomepage("https://user:pw@example.test/"); got != "" {
		t.Fatalf("NormalizeHomepage published credentials: %q", got)
	}
	if got := NormalizeHomepage("/opt/local/project"); got != "" {
		t.Fatalf("NormalizeHomepage published a local path: %q", got)
	}
}

// --- merge regressions ----------------------------------------------------

// TestPackageMergeUnionsSetValuedFields pins the two fields that used to be
// first-wins. A second matcher's CPE or a second source's license claim was
// dropped on seeding order alone, which is a matching miss rather than a
// cosmetic difference.
func TestPackageMergeUnionsSetValuedFields(t *testing.T) {
	dst := &Package{
		CPEs:     []string{"cpe:2.3:a:vendor:pkg:1.0:*:*:*:*:*:*:*"},
		Licenses: []PackageLicense{{Value: "MIT", SPDXExpression: "MIT", Type: LicenseTypeDeclared}},
	}
	src := &Package{
		CPEs:     []string{"cpe:2.3:a:other:pkg:1.0:*:*:*:*:*:*:*"},
		Licenses: []PackageLicense{{Value: "Apache-2.0", SPDXExpression: "Apache-2.0", Type: LicenseTypeConcluded}},
	}
	dst.MergeFrom(src)
	if len(dst.CPEs) != 2 {
		t.Fatalf("CPEs = %v, want both witnesses' identifiers", dst.CPEs)
	}
	if len(dst.Licenses) != 2 {
		t.Fatalf("licenses = %+v, want both witnesses' claims", dst.Licenses)
	}
}

func TestPackageMergeCarriesComponentAssertions(t *testing.T) {
	dst := &Package{}
	src := &Package{
		Description: "A tidy package.",
		Homepage:    "https://example.test",
		Supplier:    &Contact{Kind: ContactKindOrganization, Name: "Acme Inc"},
		Originator:  &Contact{Kind: ContactKindPerson, Name: "Jane Doe"},
	}
	dst.MergeFrom(src)
	if dst.Description != src.Description || dst.Homepage != src.Homepage {
		t.Fatalf("descriptive fields did not fill gaps: %+v", dst)
	}
	if dst.Supplier == nil || dst.Supplier.Name != "Acme Inc" {
		t.Fatalf("supplier did not fill the gap: %+v", dst.Supplier)
	}
	// The contact must be a copy: sharing the pointer would let a later edit
	// of one package rewrite another's supplier.
	if dst.Supplier == src.Supplier {
		t.Fatal("supplier was aliased rather than copied")
	}
	if dst.Originator == nil || dst.Originator.Name != "Jane Doe" {
		t.Fatalf("originator did not fill the gap: %+v", dst.Originator)
	}
	// An existing claim is not overwritten by a later source.
	second := &Package{Description: "Something else", Supplier: &Contact{Kind: ContactKindOrganization, Name: "Other"}}
	dst.MergeFrom(second)
	if dst.Description != "A tidy package." || dst.Supplier.Name != "Acme Inc" {
		t.Fatalf("a later source overwrote an existing claim: %+v", dst)
	}
}

// --- node carriage --------------------------------------------------------

func TestDependencyNodeCarriesComponentAssertions(t *testing.T) {
	node := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "react", Version: "18.2.0"})
	node.Description = "A JavaScript library."
	node.Homepage = "https://react.test"
	node.Supplier = &Contact{Kind: ContactKindOrganization, Name: "Meta"}
	node.Licenses = []PackageLicense{{Value: "MIT", SPDXExpression: "MIT", Type: LicenseTypeDeclared}}

	pkg := PackageFromDependencyNode(node)
	if pkg.Description != node.Description || pkg.Homepage != node.Homepage {
		t.Fatalf("seeding dropped the descriptive assertions: %+v", pkg)
	}
	if pkg.Supplier == nil || pkg.Supplier.Name != "Meta" {
		t.Fatalf("seeding dropped the supplier: %+v", pkg.Supplier)
	}
	if len(pkg.Licenses) != 1 {
		t.Fatalf("seeding dropped the license claims: %+v", pkg.Licenses)
	}
}

// TestSeedingReGatesAssertions pins that seeding is not a way around the
// boundary the wire enforces: a hand-built node with an unpublishable
// homepage or supplier must not reach the registry with it.
func TestSeedingReGatesAssertions(t *testing.T) {
	node := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "react", Version: "18.2.0"})
	node.Homepage = "https://user:pw@react.test/"
	node.Supplier = &Contact{Kind: ContactKindOrganization, Name: "Acme\nInc"}
	node.Description = "clean\x07text"

	pkg := PackageFromDependencyNode(node)
	if pkg.Homepage != "" {
		t.Fatalf("credentials reached the registry package: %q", pkg.Homepage)
	}
	if pkg.Supplier != nil {
		t.Fatalf("an unpublishable supplier reached the registry package: %+v", pkg.Supplier)
	}
	if pkg.Description != "cleantext" {
		t.Fatalf("description = %q, want the control character dropped", pkg.Description)
	}
}

func TestDependencyNodeWireCarriesComponentAssertions(t *testing.T) {
	graph := New()
	node := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "react", Version: "18.2.0"})
	node.Description = "A JavaScript library."
	node.Homepage = "https://react.test/docs?v=18"
	node.Supplier = &Contact{Kind: ContactKindOrganization, Name: "Meta"}
	node.Originator = &Contact{Kind: ContactKindPerson, Name: "Jane Doe"}
	node.Licenses = []PackageLicense{{Value: "MIT", SPDXExpression: "MIT", Type: LicenseTypeDeclared}}
	if err := graph.AddNode(node); err != nil {
		t.Fatalf("add node: %v", err)
	}

	encoded, err := json.Marshal(graph)
	if err != nil {
		t.Fatalf("encode graph: %v", err)
	}
	var decoded Graph
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("decode graph: %v", err)
	}
	round := decoded.DependencyNodes()
	if len(round) != 1 {
		t.Fatalf("decoded %d dependency nodes, want 1", len(round))
	}
	got := round[0]
	if got.Description != node.Description {
		t.Fatalf("description did not survive the wire: %q", got.Description)
	}
	if got.Homepage != node.Homepage {
		t.Fatalf("homepage did not survive the wire: %q", got.Homepage)
	}
	if got.Supplier == nil || got.Supplier.Name != "Meta" {
		t.Fatalf("supplier did not survive the wire: %+v", got.Supplier)
	}
	if got.Originator == nil || got.Originator.Name != "Jane Doe" {
		t.Fatalf("originator did not survive the wire: %+v", got.Originator)
	}
	if len(got.Licenses) != 1 || got.Licenses[0].Type != LicenseTypeDeclared {
		t.Fatalf("licenses did not survive the wire: %+v", got.Licenses)
	}
}

// TestDependencyNodeWireGatesArrivingAssertions pins that the decoder holds a
// payload to the same rules the encoder does. A plugin is an untrusted
// producer, so a homepage carrying credentials must not become a stored value
// that later code trusts because "it came from the wire".
func TestDependencyNodeWireGatesArrivingAssertions(t *testing.T) {
	payload := `{"nodes":[{"kind":"dependency","id":"pkg:npm/react@18.2.0","purl":"pkg:npm/react@18.2.0",` +
		`"homepage":"https://user:pw@react.test/","description":"bad\u0007text",` +
		`"supplier":{"kind":"organization","name":"Acme\nInc"}}]}`
	var decoded Graph
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("decode graph: %v", err)
	}
	nodes := decoded.DependencyNodes()
	if len(nodes) != 1 {
		t.Fatalf("decoded %d dependency nodes, want 1", len(nodes))
	}
	got := nodes[0]
	if got.Homepage != "" {
		t.Fatalf("credentials survived the decoder: %q", got.Homepage)
	}
	if got.Description != "badtext" {
		t.Fatalf("description = %q, want the control character dropped", got.Description)
	}
	if got.Supplier != nil && got.Supplier.Name != "" {
		t.Fatalf("an unpublishable supplier survived the decoder: %+v", got.Supplier)
	}
}

// TestDependencyFoldMergesComponentAssertions pins the fold's classes: license
// claims union across witnesses, the scalar assertions fill gaps, and an
// existing claim is not overwritten by a later witness.
func TestDependencyFoldMergesComponentAssertions(t *testing.T) {
	graph := New()
	first := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "react", Version: "18.2.0"})
	first.Licenses = []PackageLicense{{Value: "MIT", SPDXExpression: "MIT", Type: LicenseTypeDeclared}}
	first.Description = "From the lockfile."
	if err := graph.AddNode(first); err != nil {
		t.Fatalf("add first: %v", err)
	}

	second := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "react", Version: "18.2.0"})
	second.Licenses = []PackageLicense{{Value: "Apache-2.0", SPDXExpression: "Apache-2.0", Type: LicenseTypeConcluded}}
	second.Description = "From an SBOM."
	second.Homepage = "https://react.test"
	second.Supplier = &Contact{Kind: ContactKindOrganization, Name: "Meta"}
	if _, err := graph.InsertNode(second); err != nil {
		t.Fatalf("insert second: %v", err)
	}

	folded := graph.DependencyNodes()
	if len(folded) != 1 {
		t.Fatalf("folded to %d nodes, want 1", len(folded))
	}
	got := folded[0]
	if len(got.Licenses) != 2 {
		t.Fatalf("licenses = %+v, want both witnesses' claims", got.Licenses)
	}
	if got.Description != "From the lockfile." {
		t.Fatalf("description = %q, want the surviving claim kept", got.Description)
	}
	if got.Homepage != "https://react.test" {
		t.Fatalf("homepage = %q, want the second witness to fill the gap", got.Homepage)
	}
	if got.Supplier == nil || got.Supplier.Name != "Meta" {
		t.Fatalf("supplier = %+v, want the second witness to fill the gap", got.Supplier)
	}
}

// TestContactDropsAddressesWhereverTheyAppear pins the privacy rule against
// the sloppy-document case the fuzzer found: a producer that writes the
// address as the name rather than in SPDX's parenthetical must not get it
// stored. Stripping only the parenthetical would honor the decision for
// well-formed input and break it for everything else.
func TestContactDropsAddressesWhereverTheyAppear(t *testing.T) {
	// A name that is nothing but an address leaves no usable name.
	if contact, ok := ParseSPDXContact("Person: jane@example.com"); ok {
		t.Fatalf("a bare address was accepted as a name: %+v", contact)
	}
	// A name carrying an address keeps the name and drops the address.
	contact, ok := ParseSPDXContact("Person: Jane Doe jane@example.com")
	if !ok {
		t.Fatal("a contact with a real name was rejected")
	}
	if contact.Name != "Jane Doe" {
		t.Fatalf("name = %q, want the address-shaped token dropped", contact.Name)
	}
	// The rule is on the value, not on the parser: a hand-built contact is
	// held to it too.
	built, ok := (Contact{Kind: ContactKindOrganization, Name: "Acme ops@acme.test"}).Normalized()
	if !ok || built.Name != "Acme" {
		t.Fatalf("hand-built contact normalized to %+v, want the address dropped", built)
	}
}

// TestPackageLicenseRejectsBlankExtractedText pins a case the fuzzer found:
// whitespace-only text minted the reference that empty text mints, so every
// package carrying a blank license file would have shared one citation
// pointing at nothing.
func TestPackageLicenseRejectsBlankExtractedText(t *testing.T) {
	license := PackageLicense{Value: "Custom", ExtractedText: "   \n\t "}
	normalized, ok := license.Normalized()
	if !ok {
		t.Fatal("a license with a stated value was rejected")
	}
	if normalized.ExtractedText != "" {
		t.Fatalf("blank text survived as %q", normalized.ExtractedText)
	}
	if normalized.SPDXExpression != "" {
		t.Fatalf("blank text minted the citation %q", normalized.SPDXExpression)
	}
}
