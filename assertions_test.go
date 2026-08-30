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

// TestDigestAlgorithmRegistryMatchesTheSpecifications pins every row's format
// spellings against literals written out independently of the registry.
//
// This is the only guard that can catch a typo in a format column. A loop over
// digestAlgorithmProfiles cannot: the alias index is built from that same
// table, so a misspelled "ADLR32" would register itself and resolve happily to
// its own row while every exported document carried a value the format
// rejects. Checking against the table is checking the table against itself.
func TestDigestAlgorithmRegistryMatchesTheSpecifications(t *testing.T) {
	// SPDX 2.3 ChecksumAlgorithm and CycloneDX 1.5/1.6 hash-alg, transcribed
	// here a second time. An empty string means that format does not define
	// the algorithm.
	expected := map[DigestAlgorithm]struct{ spdx, cycloneDX string }{
		DigestAlgorithmMD2:        {"MD2", ""},
		DigestAlgorithmMD4:        {"MD4", ""},
		DigestAlgorithmMD5:        {"MD5", "MD5"},
		DigestAlgorithmMD6:        {"MD6", ""},
		DigestAlgorithmSHA1:       {"SHA1", "SHA-1"},
		DigestAlgorithmSHA224:     {"SHA224", ""},
		DigestAlgorithmSHA256:     {"SHA256", "SHA-256"},
		DigestAlgorithmSHA384:     {"SHA384", "SHA-384"},
		DigestAlgorithmSHA512:     {"SHA512", "SHA-512"},
		DigestAlgorithmSHA3256:    {"SHA3-256", "SHA3-256"},
		DigestAlgorithmSHA3384:    {"SHA3-384", "SHA3-384"},
		DigestAlgorithmSHA3512:    {"SHA3-512", "SHA3-512"},
		DigestAlgorithmBLAKE2b256: {"BLAKE2b-256", "BLAKE2b-256"},
		DigestAlgorithmBLAKE2b384: {"BLAKE2b-384", "BLAKE2b-384"},
		DigestAlgorithmBLAKE2b512: {"BLAKE2b-512", "BLAKE2b-512"},
		DigestAlgorithmBLAKE3:     {"BLAKE3", "BLAKE3"},
		DigestAlgorithmADLER32:    {"ADLER32", ""},
	}
	if len(expected) != len(digestAlgorithmProfiles) {
		t.Fatalf("registry holds %d rows, this test pins %d; a row was added without its spellings",
			len(digestAlgorithmProfiles), len(expected))
	}
	for algorithm, want := range expected {
		if got := algorithm.SPDXName(); got != want.spdx {
			t.Errorf("%q SPDX spelling = %q, want %q", algorithm, got, want.spdx)
		}
		if got := algorithm.CycloneDXName(); got != want.cycloneDX {
			t.Errorf("%q CycloneDX spelling = %q, want %q", algorithm, got, want.cycloneDX)
		}
		// The canonical token is itself a spelling that must resolve back.
		if got, err := ParseDigestAlgorithm(string(algorithm)); err != nil || got != algorithm {
			t.Errorf("canonical token %q resolved to %q (err=%v)", algorithm, got, err)
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
	if got.Supplier != nil {
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

// TestPackageLicenseValidatesGeneralExpressions pins that "does not start with
// LicenseRef-" is not evidence that a string is a license expression. An
// unparseable value used to survive as a typed claim and would have been
// exported into a document that fails its own validator.
func TestPackageLicenseValidatesGeneralExpressions(t *testing.T) {
	t.Run("an unparseable expression is dropped", func(t *testing.T) {
		normalized, ok := PackageLicense{Value: "weird", SPDXExpression: "not valid OR"}.Normalized()
		if !ok {
			t.Fatal("a license with a stated value was rejected outright")
		}
		if normalized.SPDXExpression != "" {
			t.Fatalf("expression = %q, want it dropped", normalized.SPDXExpression)
		}
		if normalized.Value != "weird" {
			t.Fatalf("value = %q, want the source's own statement kept", normalized.Value)
		}
	})

	t.Run("a deprecated identifier is canonicalized", func(t *testing.T) {
		// spdxkit owns the replacement map (ADR-0038); Value keeps what the
		// source said while the expression is the form Bomly will publish.
		normalized, ok := PackageLicense{Value: "GPL-2.0", SPDXExpression: "GPL-2.0"}.Normalized()
		if !ok {
			t.Fatal("a valid license was rejected")
		}
		if normalized.SPDXExpression != "GPL-2.0-only" {
			t.Fatalf("expression = %q, want the canonical identifier", normalized.SPDXExpression)
		}
		if normalized.Value != "GPL-2.0" {
			t.Fatalf("value = %q, want the source's own spelling kept", normalized.Value)
		}
	})

	t.Run("a valid expression survives", func(t *testing.T) {
		normalized, ok := PackageLicense{SPDXExpression: "MIT OR Apache-2.0"}.Normalized()
		if !ok || normalized.SPDXExpression != "MIT OR Apache-2.0" {
			t.Fatalf("normalized = %+v ok=%v, want the expression kept", normalized, ok)
		}
	})

	t.Run("a compound citing a reference needs its text", func(t *testing.T) {
		// The parser accepts "MIT OR LicenseRef-Acme", but a citation without
		// its text is the same dangling reference the bare-reference branch
		// refuses.
		normalized, ok := PackageLicense{Value: "mixed", SPDXExpression: "MIT OR LicenseRef-Acme"}.Normalized()
		if !ok {
			t.Fatal("a license with a stated value was rejected outright")
		}
		if normalized.SPDXExpression != "" {
			t.Fatalf("expression = %q, want it dropped without its text", normalized.SPDXExpression)
		}
		// With the text present it is publishable.
		withText, ok := PackageLicense{SPDXExpression: "MIT OR LicenseRef-Acme", ExtractedText: "Acme terms."}.Normalized()
		if !ok || withText.SPDXExpression != "MIT OR LicenseRef-Acme" {
			t.Fatalf("normalized = %+v ok=%v, want the compound kept once its text is present", withText, ok)
		}
	})
}

// TestRegistryGatesArrivingAssertions pins the registry's door. Package has no
// JSON codec of its own and matcher package updates cross the plugin wire as
// plain structs, so without a gate at Add a matcher could put credentials or a
// control character straight into the registry, which PackageRegistry then
// forwards to every reader.
func TestRegistryGatesArrivingAssertions(t *testing.T) {
	registry := NewPackageRegistry()
	// The first record of a PURL takes the clone path, not the merge path.
	stored := registry.Add(&Package{
		Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"},
		Homepage:    "https://user:pw@react.test/",
		Description: "bad\x07text",
		Supplier:    &Contact{Kind: ContactKindOrganization, Name: "Acme\nInc"},
		Licenses:    []PackageLicense{{Value: "x", SPDXExpression: "not valid OR"}},
		Digests:     []Digest{{Algorithm: "crc32", Value: "zz"}, {Algorithm: DigestAlgorithmSHA256, Value: "abc"}},
	})
	if stored.Homepage != "" {
		t.Fatalf("credentials entered the registry: %q", stored.Homepage)
	}
	if stored.Description != "badtext" {
		t.Fatalf("description = %q, want the control character dropped", stored.Description)
	}
	if stored.Supplier != nil {
		t.Fatalf("an unpublishable supplier entered the registry: %+v", stored.Supplier)
	}
	if len(stored.Licenses) != 1 || stored.Licenses[0].SPDXExpression != "" {
		t.Fatalf("licenses = %+v, want the unparseable expression dropped", stored.Licenses)
	}
	if len(stored.Digests) != 1 || stored.Digests[0].Algorithm != DigestAlgorithmSHA256 {
		t.Fatalf("digests = %+v, want only the publishable one", stored.Digests)
	}

	// The merge path is gated too: a second update for the same PURL fills
	// gaps, and must not fill them with an unpublishable value.
	ApplyPackageUpdates(registry, []*Package{{
		Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"},
		Homepage:    "https://user:pw@evil.test/",
		Supplier:    &Contact{Kind: ContactKindOrganization, Name: "Bad\nActor"},
	}})
	merged, _ := registry.Get("pkg:npm/react@18.2.0")
	if merged.Homepage != "" || merged.Supplier != nil {
		t.Fatalf("a matcher update carried an unpublishable assertion into the registry: %+v", merged)
	}

	// A publishable update still fills the gap -- the gate rejects, it does
	// not simply refuse everything.
	ApplyPackageUpdates(registry, []*Package{{
		Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"},
		Homepage:    "https://react.test",
	}})
	merged, _ = registry.Get("pkg:npm/react@18.2.0")
	if merged.Homepage != "https://react.test" {
		t.Fatalf("homepage = %q, want the valid update to fill the gap", merged.Homepage)
	}
}

// TestRejectedOptionalAssertionsLeaveNoEmptyWireObjects pins the two shapes
// that omitempty cannot suppress on its own: a non-nil pointer to a rejected
// value, and a rejected element inside a slice. Both would publish an empty
// object where the assertion was supposed to have been dropped.
func TestRejectedOptionalAssertionsLeaveNoEmptyWireObjects(t *testing.T) {
	payload := `{"nodes":[{"kind":"dependency","id":"pkg:npm/a@1.0.0","purl":"pkg:npm/a@1.0.0",` +
		`"supplier":{"kind":"organization"},"originator":{},` +
		`"digests":[{"algorithm":"crc32","value":"zz"},{"algorithm":"sha256","value":"abc"}]}]}`
	var decoded Graph
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("decode graph: %v", err)
	}
	node := decoded.DependencyNodes()[0]
	if node.Supplier != nil || node.Originator != nil {
		t.Fatalf("a rejected contact survived as a pointer: supplier=%+v originator=%+v", node.Supplier, node.Originator)
	}
	if len(node.Digests) != 1 || node.Digests[0].Algorithm != DigestAlgorithmSHA256 {
		t.Fatalf("digests = %+v, want only the publishable one", node.Digests)
	}

	encoded, err := json.Marshal(&decoded)
	if err != nil {
		t.Fatalf("encode graph: %v", err)
	}
	for _, forbidden := range []string{`"supplier":{}`, `"originator":{}`, `{},`, `[{}`} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("encoded graph contains %s: %s", forbidden, encoded)
		}
	}
}

// TestPackageMergeFromGatesDirectCallers pins MergeFrom's own gate. The
// registry normalizes before merging, so that path cannot reach this — but
// MergeFrom is exported and callable directly, and a caller that reaches it
// with a matcher's raw package must not get an unpublishable assertion
// installed as if it had passed a door.
func TestPackageMergeFromGatesDirectCallers(t *testing.T) {
	dst := &Package{}
	dst.MergeFrom(&Package{
		Homepage:    "https://user:pw@evil.test/",
		Description: "bad\x07text",
		Supplier:    &Contact{Kind: ContactKindOrganization, Name: "Acme\nInc"},
	})
	if dst.Homepage != "" {
		t.Fatalf("credentials survived a direct merge: %q", dst.Homepage)
	}
	if dst.Description != "badtext" {
		t.Fatalf("description = %q, want the control character dropped", dst.Description)
	}
	if dst.Supplier != nil {
		t.Fatalf("an unpublishable supplier survived a direct merge: %+v", dst.Supplier)
	}
}

// TestPackageLicenseNormalizationIsIdempotent pins a break the fuzzer caught:
// an expression dropped as unpublishable used to acquire its minted reference
// on the second pass rather than the first. Normalized runs on both marshal
// and unmarshal, so such a record changed shape every time it crossed the
// wire.
func TestPackageLicenseNormalizationIsIdempotent(t *testing.T) {
	for _, license := range []PackageLicense{
		{Value: "x", SPDXExpression: "not valid OR", ExtractedText: "Custom terms."},
		{Value: "x", SPDXExpression: "not valid OR"},
		{Value: "GPL-2.0", SPDXExpression: "GPL-2.0"},
		{SPDXExpression: "LicenseRef-Acme", ExtractedText: "Acme terms."},
		{SPDXExpression: "MIT OR LicenseRef-Acme", ExtractedText: "Acme terms."},
		{Value: "Custom", ExtractedText: "Custom terms."},
	} {
		once, ok := license.Normalized()
		if !ok {
			continue
		}
		twice, ok := once.Normalized()
		if !ok || twice != once {
			t.Fatalf("normalizing %+v twice gave %+v then %+v (ok=%v)", license, once, twice, ok)
		}
	}
	// The specific case: a rejected expression mints its citation in the
	// first pass, not the second.
	dropped, ok := PackageLicense{Value: "x", SPDXExpression: "not valid OR", ExtractedText: "Custom terms."}.Normalized()
	if !ok {
		t.Fatal("a license with text was rejected")
	}
	if dropped.SPDXExpression == "" {
		t.Fatal("text was left with no citation after its expression was dropped")
	}
}

// TestMergeLicensesKeepsCollidingReferencesApart pins that a document-local
// identifier reused by two sources for different terms does not silently lose
// one of them. Source-defined references are preserved rather than re-minted,
// so two SBOMs can each arrive naming "LicenseRef-Custom" for unrelated
// licenses; merging them on the identifier alone dropped the second document's
// text and left the survivor's identifier naming the wrong terms.
func TestMergeLicensesKeepsCollidingReferencesApart(t *testing.T) {
	merged := MergeLicenses(
		[]PackageLicense{{Value: "Custom", SPDXExpression: "LicenseRef-Custom", ExtractedText: "Doc A terms."}},
		[]PackageLicense{{Value: "Custom", SPDXExpression: "LicenseRef-Custom", ExtractedText: "Doc B terms."}},
	)
	if len(merged) != 2 {
		t.Fatalf("merged = %+v, want both documents' terms", merged)
	}
	texts := map[string]string{}
	for _, license := range merged {
		if prior, seen := texts[license.SPDXExpression]; seen {
			t.Fatalf("reference %q names two texts (%q and %q); the merged set is ambiguous",
				license.SPDXExpression, prior, license.ExtractedText)
		}
		texts[license.SPDXExpression] = license.ExtractedText
	}
	// The first claim keeps the identifier it arrived with.
	if texts["LicenseRef-Custom"] != "Doc A terms." {
		t.Fatalf("the first claim lost its identifier: %+v", texts)
	}
	// The same text twice is still one claim -- this must not turn every
	// merge into an append.
	same := MergeLicenses(
		[]PackageLicense{{Value: "Custom", SPDXExpression: "LicenseRef-Custom", ExtractedText: "Doc A terms."}},
		[]PackageLicense{{Value: "Custom", SPDXExpression: "LicenseRef-Custom", ExtractedText: "Doc A terms."}},
	)
	if len(same) != 1 {
		t.Fatalf("identical claims merged to %+v, want one", same)
	}

	// The collision resolver only rewrites license references. A listed
	// identifier carrying two different texts is the case the key itself has
	// to keep apart -- contradictions survive as distinct claims (ADR-0033)
	// rather than one being dropped for sharing an expression.
	listed := MergeLicenses(
		[]PackageLicense{{SPDXExpression: "MIT", ExtractedText: "Doc A copy of the MIT text."}},
		[]PackageLicense{{SPDXExpression: "MIT", ExtractedText: "Doc B copy of the MIT text."}},
	)
	if len(listed) != 2 {
		t.Fatalf("merged = %+v, want both texts kept under the shared identifier", listed)
	}
}

// TestFoldGatesBothWitnessesBeforeMeasuringTheGap pins the ordering. A node
// built in process never passed a codec, so a survivor can hold a value that
// is non-empty (and so blocks the gap-fill) but unpublishable (and so is
// dropped at encode) — losing a good assertion to a witness that never had one.
func TestFoldGatesBothWitnessesBeforeMeasuringTheGap(t *testing.T) {
	graph := New()
	first := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "react", Version: "18.2.0"})
	first.Homepage = "https://user:pw@evil.test/"
	first.Supplier = &Contact{Kind: ContactKindOrganization, Name: "Acme\nInc"}
	if err := graph.AddNode(first); err != nil {
		t.Fatalf("add first: %v", err)
	}

	second := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "react", Version: "18.2.0"})
	second.Homepage = "https://react.test"
	second.Supplier = &Contact{Kind: ContactKindOrganization, Name: "Meta"}
	if _, err := graph.InsertNode(second); err != nil {
		t.Fatalf("insert second: %v", err)
	}

	folded := graph.DependencyNodes()[0]
	if folded.Homepage != "https://react.test" {
		t.Fatalf("homepage = %q, want the valid witness to win over the unpublishable one", folded.Homepage)
	}
	if folded.Supplier == nil || folded.Supplier.Name != "Meta" {
		t.Fatalf("supplier = %+v, want the valid witness to win", folded.Supplier)
	}
	encoded, err := json.Marshal(graph)
	if err != nil {
		t.Fatalf("encode graph: %v", err)
	}
	if !strings.Contains(string(encoded), "https://react.test") {
		t.Fatalf("the valid homepage did not survive to the wire: %s", encoded)
	}
}

// TestRegistryMarshalReGatesMutatedRecords pins the second door. Add gates
// what comes in, but Ensure, Get, and All hand back mutable pointers and the
// established pattern is to mutate what Ensure returns, so an assertion
// installed after insertion would otherwise reach every reader unchecked.
func TestRegistryMarshalReGatesMutatedRecords(t *testing.T) {
	registry := NewPackageRegistry()
	registry.Add(&Package{Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"}})
	stored := registry.Ensure("pkg:npm/react@18.2.0")
	stored.Homepage = "https://user:pw@evil.test/"
	stored.Description = "bad\x07text"
	stored.Supplier = &Contact{Kind: ContactKindOrganization, Name: "Acme\nInc"}

	encoded, err := json.Marshal(registry)
	if err != nil {
		t.Fatalf("encode registry: %v", err)
	}
	for _, forbidden := range []string{"user:pw", "\\u0007", `"supplier"`} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("encoded registry contains %s: %s", forbidden, encoded)
		}
	}
	// Normalizing the copy must not rewrite the record its holder still owns.
	if stored.Homepage != "https://user:pw@evil.test/" {
		t.Fatalf("marshal mutated the stored record: %q", stored.Homepage)
	}
}

// TestParseDigestAlgorithmBoundsItsInput pins the bound, and that the bound is
// comfortably above every registered spelling — a limit that clipped a real
// algorithm name would be a silent correctness bug rather than a guard.
func TestParseDigestAlgorithmBoundsItsInput(t *testing.T) {
	// The error must come from the bound, not from the registry lookup that
	// would reject it anyway: the point is that an arbitrarily large token is
	// refused before it is lowercased and copied into a squashed key, so
	// asserting only "it errors" would pass with the bound removed.
	_, err := ParseDigestAlgorithm(strings.Repeat("a", maxDigestAlgorithmLength+1))
	if err == nil {
		t.Fatal("an over-long algorithm token was accepted")
	}
	if !strings.Contains(err.Error(), "over the") {
		t.Fatalf("error = %v, want the length bound to have rejected it before the lookup", err)
	}
	for _, profile := range digestAlgorithmProfiles {
		for _, spelling := range []string{string(profile.canonical), profile.spdx, profile.cycloneDX} {
			if len(spelling) > maxDigestAlgorithmLength {
				t.Fatalf("registered spelling %q is %d bytes, over the parse limit", spelling, len(spelling))
			}
		}
	}
}

// TestContactPreservesNonEmailParentheticals pins a round-trip break the
// fuzzer caught: stripping every trailing "(...)" group meant a name that
// legitimately ends in one lost it on the *second* read, so a contact exported
// and re-ingested did not survive its own round trip.
func TestContactPreservesNonEmailParentheticals(t *testing.T) {
	contact, ok := ParseSPDXContact("Organization: Acme Inc (Europe)")
	if !ok {
		t.Fatal("a valid supplier was rejected")
	}
	if contact.Name != "Acme Inc (Europe)" {
		t.Fatalf("name = %q, want the qualifier preserved", contact.Name)
	}
	// Exporting and re-reading reaches the same value.
	again, ok := ParseSPDXContact(contact.SPDXString())
	if !ok || again != contact {
		t.Fatalf("round trip gave %+v (ok=%v), want %+v", again, ok, contact)
	}
	// An address parenthetical is still stripped.
	withEmail, ok := ParseSPDXContact("Organization: Acme Inc (info@acme.com)")
	if !ok || withEmail.Name != "Acme Inc" {
		t.Fatalf("name = %+v, want the address parenthetical removed", withEmail)
	}
}

// TestReferenceURLRejectsRawQueryWhitespace pins the other fixed-point break
// the fuzzer caught. A URL's query is the one part url.URL writes back
// verbatim rather than re-encoding, so a raw space survived one pass and was
// trimmed on the next -- and this rule runs on both write and read.
func TestReferenceURLRejectsRawQueryWhitespace(t *testing.T) {
	for _, raw := range []string{"http://0? #", "https://example.test/docs?a= b", "https://example.test/?\x01"} {
		if got, ok := NormalizeURL(raw, URLFormReference); ok {
			// If it is accepted at all, it must at least be a fixed point.
			again, _ := NormalizeURL(got, URLFormReference)
			t.Fatalf("NormalizeURL(%q, reference) = %q, which re-normalizes to %q", raw, got, again)
		}
	}
	// An escaped space is fine: it round-trips as written.
	got, ok := NormalizeURL("https://example.test/docs?a=%20b", URLFormReference)
	if !ok {
		t.Fatal("an escaped query space was rejected")
	}
	again, ok := NormalizeURL(got, URLFormReference)
	if !ok || again != got {
		t.Fatalf("re-normalizing %q gave %q (ok=%v)", got, again, ok)
	}
}

// TestMergeLicensesResolvesEmbeddedReferenceCollisions pins that a reference
// reused inside a compound expression is separated too. The earlier fix only
// looked at expressions that *begin* with the prefix, so "MIT OR
// LicenseRef-Custom" from two documents kept one identifier naming two texts.
func TestMergeLicensesResolvesEmbeddedReferenceCollisions(t *testing.T) {
	merged := MergeLicenses(
		[]PackageLicense{{SPDXExpression: "MIT OR LicenseRef-Custom", ExtractedText: "Doc A terms."}},
		[]PackageLicense{{SPDXExpression: "MIT OR LicenseRef-Custom", ExtractedText: "Doc B terms."}},
	)
	if len(merged) != 2 {
		t.Fatalf("merged = %+v, want both documents' terms", merged)
	}
	if merged[0].SPDXExpression == merged[1].SPDXExpression {
		t.Fatalf("both claims kept the expression %q, which now names two texts", merged[0].SPDXExpression)
	}
	// The rest of the compound is untouched -- only the reference is rewritten.
	if !strings.HasPrefix(merged[1].SPDXExpression, "MIT OR LicenseRef-bomly-") {
		t.Fatalf("rewritten expression = %q, want only the reference replaced", merged[1].SPDXExpression)
	}
	// The first claim keeps the identifier it arrived with.
	if merged[0].SPDXExpression != "MIT OR LicenseRef-Custom" {
		t.Fatalf("first claim = %q, want its own identifier preserved", merged[0].SPDXExpression)
	}
}

// TestPackageLicenseRefusesMultipleReferences pins the modelling limit
// honestly: a record carries one ExtractedText, so an expression naming two
// references cannot supply the text for both and at least one citation in it
// would dangle.
func TestPackageLicenseRefusesMultipleReferences(t *testing.T) {
	normalized, ok := PackageLicense{
		Value: "dual custom",
		// Deliberately not *starting* with a reference: an expression that
		// does is already re-minted by the bare-reference branch, so it would
		// not exercise this rule at all.
		SPDXExpression: "MIT AND LicenseRef-A AND LicenseRef-B",
		ExtractedText:  "Only one text.",
	}.Normalized()
	if !ok {
		t.Fatal("a license with a stated value was rejected outright")
	}
	// The source's two-reference expression does not survive: neither of its
	// identifiers can be published when only one of them has text.
	for _, ref := range []string{"LicenseRef-A", "LicenseRef-B"} {
		if strings.Contains(normalized.SPDXExpression, ref) {
			t.Fatalf("expression = %q, want %q refused: one text cannot name two references", normalized.SPDXExpression, ref)
		}
	}
	// The text is not lost with it -- it mints its own citation, so the terms
	// stay exportable under an identifier that resolves.
	if normalized.SPDXExpression != spdxkit.MintLicenseRef("Only one text.").RefID {
		t.Fatalf("expression = %q, want the text's own minted citation", normalized.SPDXExpression)
	}
	if normalized.Value != "dual custom" {
		t.Fatalf("value = %q, want the source's statement kept", normalized.Value)
	}
	if strings.Contains(normalized.SPDXExpression, "MIT") {
		t.Fatalf("expression = %q, want the whole compound refused, not partially kept", normalized.SPDXExpression)
	}
	// A single embedded reference is still fine.
	single, ok := PackageLicense{SPDXExpression: "MIT OR LicenseRef-A", ExtractedText: "Terms."}.Normalized()
	if !ok || single.SPDXExpression != "MIT OR LicenseRef-A" {
		t.Fatalf("normalized = %+v ok=%v, want a single embedded reference kept", single, ok)
	}
}

// TestPackageMergeFromGatesItsDestination pins the same ordering rule the fold
// follows. Ensure, Get, and All hand back mutable pointers, so the destination
// can hold a value that is non-empty (blocking the fill) yet unpublishable
// (dropped at marshal) -- losing a valid update to a value no reader sees.
func TestPackageMergeFromGatesItsDestination(t *testing.T) {
	dst := &Package{
		Homepage:    "https://user:pw@evil.test/",
		Description: strings.Repeat("a", maxDescriptionLength+1),
		Supplier:    &Contact{Kind: ContactKindOrganization, Name: "Acme\nInc"},
	}
	dst.MergeFrom(&Package{
		Homepage:    "https://good.test",
		Description: "A tidy package.",
		Supplier:    &Contact{Kind: ContactKindOrganization, Name: "Meta"},
	})
	if dst.Homepage != "https://good.test" {
		t.Fatalf("homepage = %q, want the valid update to win over the unpublishable value", dst.Homepage)
	}
	if dst.Description != "A tidy package." {
		t.Fatalf("description = %q, want the valid update to win", dst.Description)
	}
	if dst.Supplier == nil || dst.Supplier.Name != "Meta" {
		t.Fatalf("supplier = %+v, want the valid update to win", dst.Supplier)
	}
}

// TestPackageLicenseKeepsCompoundOperandOrderIrrelevant pins that a compound
// expression is treated as an expression whichever operand comes first.
// Testing the prefix alone routed "LicenseRef-Acme OR MIT" into the bare
// reference branch, where it failed the idstring check and was replaced whole
// by a minted reference — dropping "OR MIT", while the same claim written the
// other way round survived intact.
func TestPackageLicenseKeepsCompoundOperandOrderIrrelevant(t *testing.T) {
	for _, expression := range []string{"LicenseRef-Acme OR MIT", "MIT OR LicenseRef-Acme"} {
		normalized, ok := PackageLicense{SPDXExpression: expression, ExtractedText: "Acme terms."}.Normalized()
		if !ok {
			t.Fatalf("%q was rejected", expression)
		}
		if normalized.SPDXExpression != expression {
			t.Fatalf("%q normalized to %q; operand order must not decide what is kept", expression, normalized.SPDXExpression)
		}
	}
	// A bare reference is still handled as one: Bomly's own is re-minted from
	// its text, and a malformed one is replaced rather than written verbatim.
	minted := spdxkit.MintLicenseRef("Acme terms.").RefID
	malformed, ok := PackageLicense{SPDXExpression: `LicenseRef-Acme Commercial "v2"`, ExtractedText: "Acme terms."}.Normalized()
	if !ok || malformed.SPDXExpression != minted {
		t.Fatalf("malformed reference normalized to %+v, want the minted citation", malformed)
	}
	source, ok := PackageLicense{SPDXExpression: "LicenseRef-Acme", ExtractedText: "Acme terms."}.Normalized()
	if !ok || source.SPDXExpression != "LicenseRef-Acme" {
		t.Fatalf("a bare source-defined reference normalized to %+v, want it preserved", source)
	}
}

// TestContactURLCarriesNoAddress pins the privacy rule against the one place
// an address could still reach a stored contact: NormalizeURL rejects an
// address in the userinfo position, but the reference form keeps the path,
// query, and fragment.
func TestContactURLCarriesNoAddress(t *testing.T) {
	for _, raw := range []string{
		"https://acme.test/contact?email=jane@example.com",
		"https://acme.test/contact?email=jane%40example.com",
		"https://acme.test/#write-to-jane@example.com",
	} {
		contact, ok := (Contact{Kind: ContactKindOrganization, Name: "Acme", URL: raw}).Normalized()
		if !ok {
			t.Fatalf("contact with URL %q was rejected outright; the name should survive", raw)
		}
		if contact.URL != "" {
			t.Fatalf("URL %q kept an address: %q", raw, contact.URL)
		}
	}
	// The rule must not catch the shapes that merely contain "@": an npm
	// scope path and a coordinate are both common and neither is an address.
	for _, raw := range []string{
		"https://npmjs.test/package/@scope/pkg",
		"https://acme.test/releases/pkg@1.0.0",
		"https://acme.test/",
	} {
		contact, ok := (Contact{Kind: ContactKindOrganization, Name: "Acme", URL: raw}).Normalized()
		if !ok || contact.URL != raw {
			t.Fatalf("URL %q was dropped as an address: %+v (ok=%v)", raw, contact, ok)
		}
	}
}

// TestPackageUpdatesAreGatedOnTheWire pins the path the registry gate could
// never cover. A matcher or analyzer returns PackageUpdates on its result, and
// the plugin transport serializes those directly — never through
// PackageRegistry — so a gate that lived only at the registry let a
// credential-bearing homepage cross the wire and let already-rejected contacts
// and digests encode as empty "{}" objects.
func TestPackageUpdatesAreGatedOnTheWire(t *testing.T) {
	result := MatchResult{PackageUpdates: []*Package{{
		Coordinates: Coordinates{PURL: "pkg:npm/a@1.0.0"},
		Homepage:    "https://user:pw@evil.test/",
		Description: "bad\x07text",
		Supplier:    &Contact{Kind: ContactKindOrganization},
		Digests: []Digest{
			{Algorithm: "crc32", Value: "zz"},
			{Algorithm: DigestAlgorithmSHA256, Value: "ok"},
		},
	}}}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("encode result: %v", err)
	}
	for _, forbidden := range []string{"user:pw", "\\u0007", `"supplier"`, "{}"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("serialized package updates contain %s: %s", forbidden, encoded)
		}
	}
	if !strings.Contains(string(encoded), `"value":"ok"`) {
		t.Fatalf("the publishable digest was dropped too: %s", encoded)
	}

	// The gate applies on the way in as well.
	var decoded Package
	if err := json.Unmarshal([]byte(`{"purl":"pkg:npm/a@1.0.0","homepage":"https://user:pw@evil.test/"}`), &decoded); err != nil {
		t.Fatalf("decode package: %v", err)
	}
	if decoded.Homepage != "" {
		t.Fatalf("credentials survived the package decoder: %q", decoded.Homepage)
	}

	// Marshaling must not rewrite the record its holder still owns.
	held := &Package{Coordinates: Coordinates{PURL: "pkg:npm/a@1.0.0"}, Homepage: "https://user:pw@evil.test/"}
	if _, err := json.Marshal(held); err != nil {
		t.Fatalf("encode package: %v", err)
	}
	if held.Homepage != "https://user:pw@evil.test/" {
		t.Fatalf("marshaling mutated the caller's record: %q", held.Homepage)
	}
}

// TestDigestRejectsUnknownSubjects pins the closed subject vocabulary. An
// unrecognized subject cannot be cleared to the zero value instead: empty
// means "the published artifact", so treating an uninterpretable label as
// absent would publish a claim about what the hash covers that its producer
// never made.
func TestDigestRejectsUnknownSubjects(t *testing.T) {
	var digest Digest
	if err := json.Unmarshal([]byte(`{"algorithm":"sha256","value":"abc","subject":"archive"}`), &digest); err != nil {
		t.Fatalf("decode digest: %v", err)
	}
	if digest != (Digest{}) {
		t.Fatalf("an unknown subject decoded to %+v, want the digest dropped", digest)
	}
	// Validate reports it too, for a caller that asks directly rather than
	// going through the codec.
	if err := (Digest{Algorithm: DigestAlgorithmSHA256, Value: "abc", Subject: "archive"}).Validate(); err == nil {
		t.Fatal("Validate accepted an unknown subject")
	}
	// The three declared subjects still round-trip.
	for _, subject := range []DigestSubject{DigestSubjectArtifact, DigestSubjectSourceTree, DigestSubjectMetadata} {
		normalized, ok := Digest{Algorithm: DigestAlgorithmSHA256, Value: "abc", Subject: subject}.Normalized()
		if !ok || normalized.Subject != subject {
			t.Fatalf("subject %q was rejected: %+v ok=%v", subject, normalized, ok)
		}
	}
	// A declared subject spelled differently is normalized rather than
	// rejected: the parse is what makes the vocabulary usable, not only what
	// closes it.
	normalized, ok := Digest{Algorithm: DigestAlgorithmSHA256, Value: "abc", Subject: "  SOURCE-TREE  "}.Normalized()
	if !ok || normalized.Subject != DigestSubjectSourceTree {
		t.Fatalf("a padded, upper-case subject normalized to %+v (ok=%v), want %q", normalized, ok, DigestSubjectSourceTree)
	}
}

// TestMergeLicensesTreatsWhitespaceVariantsAsOneText pins the comparison
// MintLicenseRef implies. It collapses whitespace before hashing, so two texts
// differing only in spacing name the same license; comparing raw bytes sent
// them down the re-mint path, where the mint equals the reference already in
// hand and the assignment changes nothing — leaving one reference naming two
// texts, the exact ambiguity the resolver exists to prevent.
func TestMergeLicensesTreatsWhitespaceVariantsAsOneText(t *testing.T) {
	merged := MergeLicenses(
		[]PackageLicense{{Value: "A", ExtractedText: "Custom terms."}},
		[]PackageLicense{{Value: "B", ExtractedText: "Custom    terms."}},
	)
	if len(merged) != 2 {
		t.Fatalf("merged = %+v, want both claims (their Values differ)", merged)
	}
	if merged[0].SPDXExpression != merged[1].SPDXExpression {
		t.Fatalf("one license got two references: %q and %q", merged[0].SPDXExpression, merged[1].SPDXExpression)
	}
	if merged[0].ExtractedText != merged[1].ExtractedText {
		t.Fatalf("one reference names two texts: %q and %q", merged[0].ExtractedText, merged[1].ExtractedText)
	}
}
