package sdk

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk/spdxkit"
)

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

// TestLicenseReferenceBoundHoldsInsideExpressions pins a divergence the fuzzer
// found. ValidLicenseRef bounds an identifier's length, because a value far
// longer than any real reference is a payload wearing the prefix rather than
// an identifier. The expression parser applies no such bound, so the same
// reference was refused when it stood alone and published when it appeared
// inside an expression.
func TestLicenseReferenceBoundHoldsInsideExpressions(t *testing.T) {
	oversized := spdxkit.LicenseRefPrefix + strings.Repeat("A", 300)
	if spdxkit.ValidLicenseRef(oversized) {
		t.Fatal("fixture is not oversized; the bound must reject it")
	}
	for _, expression := range []string{oversized, "MIT OR " + oversized} {
		normalized, ok := PackageLicense{SPDXExpression: expression, ExtractedText: "Terms."}.Normalized()
		if !ok {
			t.Fatalf("%q was rejected outright", expression)
		}
		if strings.Contains(normalized.SPDXExpression, oversized) {
			t.Fatalf("an oversized reference survived in %q", normalized.SPDXExpression)
		}
		// The text is not lost with it.
		if normalized.SPDXExpression != spdxkit.MintLicenseRef("Terms.").RefID {
			t.Fatalf("expression = %q, want the text's own minted citation", normalized.SPDXExpression)
		}
	}
}

// TestMergeLicensesFillsMissingNames pins that deduplicating one claim does
// not throw away the only human-readable label. Name is not part of the
// identity — two records naming one license are one claim — so dropping the
// later record wholesale lost the name, which matters most for a LicenseRef-*
// claim where a reader otherwise has only "LicenseRef-bomly-3f2a..." to go on.
func TestMergeLicensesFillsMissingNames(t *testing.T) {
	merged := MergeLicenses(
		[]PackageLicense{{Value: "Custom", SPDXExpression: "LicenseRef-Acme", ExtractedText: "Acme terms."}},
		[]PackageLicense{{Value: "Custom", SPDXExpression: "LicenseRef-Acme", ExtractedText: "Acme terms.", Name: "Acme Commercial License"}},
	)
	if len(merged) != 1 {
		t.Fatalf("merged = %+v, want one claim: the name is not part of the identity", merged)
	}
	if merged[0].Name != "Acme Commercial License" {
		t.Fatalf("name = %q, want the later witness to fill the gap", merged[0].Name)
	}
	// An existing name is not overwritten by a later witness.
	kept := MergeLicenses(
		[]PackageLicense{{Value: "Custom", SPDXExpression: "LicenseRef-Acme", ExtractedText: "Acme terms.", Name: "First"}},
		[]PackageLicense{{Value: "Custom", SPDXExpression: "LicenseRef-Acme", ExtractedText: "Acme terms.", Name: "Second"}},
	)
	if len(kept) != 1 || kept[0].Name != "First" {
		t.Fatalf("merged = %+v, want the surviving name kept", kept)
	}
}

// TestBomlyReferencesAreDerivedInsideCompoundsToo pins the invariant an "OR"
// used to suspend. A reference under Bomly's prefix is derived from its text
// wherever it appears; validating it and moving on let a stale or spoofed one
// ride inside a compound and name a license its text does not mint.
func TestBomlyReferencesAreDerivedInsideCompoundsToo(t *testing.T) {
	stale := spdxkit.BomlyLicenseRefPrefix + "00000000000000000000000000000000"
	minted := spdxkit.MintLicenseRef("Real terms.").RefID
	if stale == minted {
		t.Fatal("fixture is not stale")
	}
	normalized, ok := PackageLicense{SPDXExpression: "MIT OR " + stale, ExtractedText: "Real terms."}.Normalized()
	if !ok {
		t.Fatal("a license with text was rejected")
	}
	if strings.Contains(normalized.SPDXExpression, stale) {
		t.Fatalf("a stale Bomly reference survived inside a compound: %q", normalized.SPDXExpression)
	}
	if normalized.SPDXExpression != "MIT OR "+minted {
		t.Fatalf("expression = %q, want only the reference rewritten", normalized.SPDXExpression)
	}
	// A reference that already agrees with its text is left exactly as it is.
	agreeing := "MIT OR " + minted
	same, ok := PackageLicense{SPDXExpression: agreeing, ExtractedText: "Real terms."}.Normalized()
	if !ok || same.SPDXExpression != agreeing {
		t.Fatalf("an agreeing reference was rewritten to %q", same.SPDXExpression)
	}
}

// TestPackageMergeFromNormalizesDigests pins that a direct caller gets the
// gated set merge. MergeFrom is exported and the registry is not its only
// caller, so a hand-built package must not install a rejected digest or a
// second, differently-spelled copy of one already held.
func TestPackageMergeFromNormalizesDigests(t *testing.T) {
	dst := &Package{Digests: []Digest{{Algorithm: DigestAlgorithmSHA256, Value: "abc"}}}
	dst.MergeFrom(&Package{Digests: []Digest{
		{Algorithm: "SHA-256", Value: "abc"}, // the same claim, spelled the CycloneDX way
		{Algorithm: "crc32", Value: "zz"},    // unpublishable
		{Algorithm: "SHA-1", Value: "def"},   // a genuinely new claim
	}})
	if len(dst.Digests) != 2 {
		t.Fatalf("digests = %+v, want the duplicate collapsed and the reject dropped", dst.Digests)
	}
	for _, digest := range dst.Digests {
		if !digest.Algorithm.Valid() {
			t.Fatalf("an unpublishable digest survived: %+v", digest)
		}
	}
}

// TestOversizedSPDXExpressionNeverSurvives pins the outcome, which two layers
// currently enforce: spdxkit bounds every entry point before it parses, and
// normalizedSPDXExpression declines early so an oversized value is not scanned
// three times on its way to the same answer.
//
// Removing either guard alone leaves this passing, and that is the point of
// asserting the outcome rather than the mechanism: the invariant is that an
// oversized expression never reaches a published field, so if spdxkit's own
// limit were ever loosened this test would still be the thing that catches it.
func TestOversizedSPDXExpressionNeverSurvives(t *testing.T) {
	oversized := strings.Repeat("MIT OR ", 200000) + "MIT"
	if spdxkit.WithinBounds(oversized) {
		t.Fatal("fixture is within bounds; it proves nothing")
	}
	normalized, ok := PackageLicense{Value: "stated", SPDXExpression: oversized}.Normalized()
	if !ok {
		t.Fatal("the stated value should survive on its own")
	}
	if normalized.SPDXExpression != "" {
		t.Fatalf("an oversized expression survived: %d bytes", len(normalized.SPDXExpression))
	}
}

// TestDetectionLicensesSurviveBothRecordings pins that introducing the typed
// field did not strand the established API. A detector calling
// SetDetectionLicenses used to write only the metadata stash, which the new
// seeding path did not read — so those claims reached the registry as a
// package with no licenses at all.
func TestDetectionLicensesSurviveBothRecordings(t *testing.T) {
	t.Run("through the helper", func(t *testing.T) {
		dep := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "react", Version: "18.2.0"})
		SetDetectionLicenses(dep, []PackageLicense{{Value: "MIT", SPDXExpression: "MIT", Type: LicenseTypeDeclared}})
		if len(dep.Licenses) != 1 {
			t.Fatalf("the helper did not record on the typed field: %+v", dep.Licenses)
		}
		if got := PackageFromDependencyNode(dep).Licenses; len(got) != 1 {
			t.Fatalf("seeded licenses = %+v, want the recorded claim", got)
		}
	})

	t.Run("from an older producer's stash", func(t *testing.T) {
		// A node decoded from a payload written before the typed field
		// existed, or built by a component still pinned to an earlier SDK.
		dep := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "left-pad", Version: "1.3.0"})
		dep.Metadata = map[string]any{
			MetadataKeyDetectionLicenses: []PackageLicense{{Value: "ISC", SPDXExpression: "ISC"}},
		}
		if got := DetectionLicenses(dep); len(got) != 1 {
			t.Fatalf("DetectionLicenses = %+v, want the stashed claim", got)
		}
		if got := PackageFromDependencyNode(dep).Licenses; len(got) != 1 {
			t.Fatalf("seeded licenses = %+v, want the stashed claim", got)
		}
	})

	t.Run("both, without duplication", func(t *testing.T) {
		dep := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "react", Version: "18.2.0"})
		SetDetectionLicenses(dep, []PackageLicense{{Value: "MIT", SPDXExpression: "MIT"}})
		dep.Metadata = map[string]any{
			MetadataKeyDetectionLicenses: []PackageLicense{
				{Value: "MIT", SPDXExpression: "MIT"},               // the same claim
				{Value: "Apache-2.0", SPDXExpression: "Apache-2.0"}, // a second one
			},
		}
		if got := DetectionLicenses(dep); len(got) != 2 {
			t.Fatalf("DetectionLicenses = %+v, want the union without a duplicate", got)
		}
	})
}

// TestMergeLicensesReGatesExistingClaims pins that an empty update still
// gates what is already held. MergeLicenses used to return the existing slice
// untouched when there was nothing to add, so a claim that never passed the
// gate — from a hand-built package, or one mutated through Ensure — stayed
// visible to in-process consumers like LicenseValues, which would report a
// license the wire refuses to publish.
func TestMergeLicensesReGatesExistingClaims(t *testing.T) {
	pkg := &Package{Licenses: []PackageLicense{
		{Value: "x", SPDXExpression: "not valid OR", Type: "invented"},
	}}
	pkg.MergeFrom(&Package{}) // an update carrying no licenses at all
	if len(pkg.Licenses) != 1 {
		t.Fatalf("licenses = %+v, want the stated value kept", pkg.Licenses)
	}
	if pkg.Licenses[0].SPDXExpression != "" {
		t.Fatalf("an unparseable expression survived an empty merge: %q", pkg.Licenses[0].SPDXExpression)
	}
	if pkg.Licenses[0].Type != "" {
		t.Fatalf("an unrecognized provenance survived an empty merge: %q", pkg.Licenses[0].Type)
	}
	for _, value := range pkg.LicenseValues() {
		if value == "not valid OR" {
			t.Fatal("LicenseValues reports a license the wire would refuse")
		}
	}
	// Two empty sides stay empty rather than allocating.
	if got := MergeLicenses(nil, nil); got != nil {
		t.Fatalf("MergeLicenses(nil, nil) = %+v, want nil", got)
	}
}

// TestClosedVocabulariesBoundTheirInput pins that every closed vocabulary
// refuses an oversized token before lowercasing it and formatting it into an
// error the caller discards.
func TestClosedVocabulariesBoundTheirInput(t *testing.T) {
	oversized := strings.Repeat("x", maxVocabularyTokenLength+1)
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"ParseLicenseType", func() error { _, err := ParseLicenseType(oversized); return err }()},
		{"ParseDigestSubject", func() error { _, err := ParseDigestSubject(oversized); return err }()},
		{"ParseContactKind", func() error { _, err := ParseContactKind(strings.Repeat("x", maxContactKindLength+1)); return err }()},
	} {
		if tc.err == nil {
			t.Fatalf("%s accepted an oversized token", tc.name)
		}
		if !strings.Contains(tc.err.Error(), "over the") {
			t.Fatalf("%s error = %v, want the bound to have rejected it", tc.name, tc.err)
		}
		if len(tc.err.Error()) > 200 {
			t.Fatalf("%s error is %d bytes; it echoes the input back", tc.name, len(tc.err.Error()))
		}
	}
	// Every declared token fits comfortably under the bound.
	for _, token := range []string{
		string(LicenseTypeDeclared), string(LicenseTypeConcluded),
		string(DigestSubjectSourceTree), string(DigestSubjectMetadata),
		string(ContactKindOrganization), string(ContactKindPerson), string(ContactKindNoAssertion),
	} {
		if len(token) > maxVocabularyTokenLength {
			t.Fatalf("declared token %q is over the vocabulary bound", token)
		}
	}
}

// TestLegacyDetectionLicensesSurviveTheWireAndTheFold pins the two paths that
// silently lost claims recorded through the deprecated metadata stash. After
// JSON decoding the stash is []any of map[string]any, so a typed assertion
// found nothing; and during a fold, metadata merging keeps the survivor's
// value, so the incoming witness's claims were dropped before seeding.
func TestLegacyDetectionLicensesSurviveTheWireAndTheFold(t *testing.T) {
	t.Run("across a JSON round trip", func(t *testing.T) {
		graph := New()
		dep := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "a", Version: "1.0.0"})
		dep.Metadata = map[string]any{
			MetadataKeyDetectionLicenses: []PackageLicense{{Value: "ISC", SPDXExpression: "ISC"}},
		}
		if err := graph.AddNode(dep); err != nil {
			t.Fatalf("add node: %v", err)
		}
		encoded, err := json.Marshal(graph)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		var decoded Graph
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("decode: %v", err)
		}
		got := DetectionLicenses(decoded.DependencyNodes()[0])
		if len(got) != 1 || got[0].SPDXExpression != "ISC" {
			t.Fatalf("DetectionLicenses = %+v, want the stashed claim to survive the wire", got)
		}
	})

	t.Run("across a fold", func(t *testing.T) {
		graph := New()
		first := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "b", Version: "1.0.0"})
		first.Metadata = map[string]any{
			MetadataKeyDetectionLicenses: []PackageLicense{{Value: "MIT", SPDXExpression: "MIT"}},
		}
		if err := graph.AddNode(first); err != nil {
			t.Fatalf("add first: %v", err)
		}
		second := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "b", Version: "1.0.0"})
		second.Metadata = map[string]any{
			MetadataKeyDetectionLicenses: []PackageLicense{{Value: "Apache-2.0", SPDXExpression: "Apache-2.0"}},
		}
		if _, err := graph.InsertNode(second); err != nil {
			t.Fatalf("insert second: %v", err)
		}
		got := DetectionLicenses(graph.DependencyNodes()[0])
		if len(got) != 2 {
			t.Fatalf("DetectionLicenses = %+v, want both witnesses' stashed claims", got)
		}
		if seeded := PackageFromDependencyNode(graph.DependencyNodes()[0]).Licenses; len(seeded) != 2 {
			t.Fatalf("seeded licenses = %+v, want both claims to reach the registry", seeded)
		}
	})
}

// TestLicenseSourceIsGated pins the source's domain. It is a component name,
// and "My Matcher" is a valid component -- so gating this as a single short
// token would silently erase the provenance of a legitimately named matcher.
// What is enforced is what publication needs, which is the same domain
// descriptor validation holds a name to (TestComponentNameIsBounded pins the
// two agreeing).
func TestLicenseSourceIsGated(t *testing.T) {
	// Refused: a control character would corrupt SPDX's line-oriented tag
	// form, and an unbounded value is not a name.
	for _, source := range []string{
		"with\ttab", "with\nnewline", strings.Repeat("s", maxLicenseSourceLength+1),
	} {
		got, ok := PackageLicense{Value: "MIT", Source: source}.Normalized()
		if !ok {
			t.Fatalf("source %q took the whole license with it", source)
		}
		if got.Source != "" {
			t.Errorf("source %q survived as %q", source, got.Source)
		}
	}
	// Kept: whitespace inside a name is legal, and a name longer than a
	// vocabulary token is still a name.
	for _, source := range []string{
		"external-depsdev",
		"My Matcher",
		strings.Repeat("s", maxVocabularyTokenLength+1),
	} {
		got, ok := PackageLicense{Value: "MIT", Source: source}.Normalized()
		if !ok || got.Source != source {
			t.Errorf("source %q was erased (ok=%v, got %q); a valid component name must survive", source, ok, got.Source)
		}
	}
	// Surrounding space is trimmed rather than costing the value.
	got, ok := PackageLicense{Value: "MIT", Source: "  external-depsdev  "}.Normalized()
	if !ok {
		t.Fatal("a license with a clean source was dropped")
	}
	if got.Source != "external-depsdev" {
		t.Errorf("Source = %q, want the trimmed name", got.Source)
	}
}

// TestLicenseSourceSurvivesAMerge pins the merge class. Source is not part of
// the merge identity, so an unsourced copy of a claim and a matcher-sourced
// copy are one claim -- and without a fill-gaps rule, whichever arrived first
// decided whether the provenance survived. That made the fix order-dependent
// through Package.MergeFrom and SetDetectionLicenses.
func TestLicenseSourceSurvivesAMerge(t *testing.T) {
	unsourced := PackageLicense{Value: "MIT", SPDXExpression: "MIT", Type: LicenseTypeDeclared}
	sourced := PackageLicense{Value: "MIT", SPDXExpression: "MIT", Type: LicenseTypeDeclared, Source: "external-depsdev"}

	for _, tc := range []struct {
		name          string
		first, second []PackageLicense
	}{
		{"unsourced first", []PackageLicense{unsourced}, []PackageLicense{sourced}},
		{"sourced first", []PackageLicense{sourced}, []PackageLicense{unsourced}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			merged := MergeLicenses(tc.first, tc.second)
			if len(merged) != 1 {
				t.Fatalf("merged into %d claims, want one: %+v", len(merged), merged)
			}
			if merged[0].Source != "external-depsdev" {
				t.Errorf("Source = %q, want the provenance carried whichever side had it", merged[0].Source)
			}
		})
	}
}

func TestPackageRemediationCloneAndJSON(t *testing.T) {
	original := &Package{
		Coordinates: Coordinates{PURL: "pkg:npm/example@1.0.0"},
		Remediation: &PackageRemediation{
			Status:             PackageRemediationComplete,
			RecommendedVersion: "1.2.0",
			Suggestions: []PackageRemediationSuggestion{{
				AffectedDependencyRefs:       []string{"dependency-a", "dependency-b"},
				SuggestedActionDependencyRef: "dependency-a",
				ManifestPath:                 "package-lock.json",
				Action:                       RemediationActionDirectBump,
			}},
		},
	}

	clone := original.Clone()
	if clone.Remediation == original.Remediation {
		t.Fatal("Clone() reused the remediation pointer")
	}
	clone.Remediation.RecommendedVersion = "2.0.0"
	clone.Remediation.Suggestions[0].AffectedDependencyRefs[0] = "mutated"
	if original.Remediation.RecommendedVersion != "1.2.0" {
		t.Fatalf("Clone() mutated original remediation: %#v", original.Remediation)
	}
	if original.Remediation.Suggestions[0].AffectedDependencyRefs[0] != "dependency-a" {
		t.Fatalf("Clone() shared suggestion dependency refs: %#v", original.Remediation)
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	jsonValue := string(data)
	if !strings.Contains(jsonValue, `"remediation":{"status":"complete","recommended_version":"1.2.0","suggestions":[`) {
		t.Fatalf("Marshal() omitted remediation fields: %s", data)
	}
	if !strings.Contains(jsonValue, `"action":"direct-bump"`) {
		t.Fatalf("Marshal() omitted remediation suggestion: %s", data)
	}
	if !strings.Contains(jsonValue, `"affected_dependency_refs":["dependency-a","dependency-b"]`) ||
		!strings.Contains(jsonValue, `"suggested_action_dependency_ref":"dependency-a"`) {
		t.Fatalf("Marshal() used unclear remediation references: %s", data)
	}
	if strings.Contains(jsonValue, `"dependency_refs"`) ||
		strings.Contains(jsonValue, `"target_dependency_ref"`) {
		t.Fatalf("Marshal() retained obsolete remediation reference names: %s", data)
	}
}

func TestPackageRemediationJSONOmitsEmptyValues(t *testing.T) {
	data, err := json.Marshal(&Package{
		Coordinates: Coordinates{PURL: "pkg:npm/example@1.0.0"},
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if strings.Contains(string(data), `"remediation"`) {
		t.Fatalf("Marshal() included nil remediation: %s", data)
	}

	data, err = json.Marshal(&Package{
		Coordinates: Coordinates{PURL: "pkg:npm/example@1.0.0"},
		Remediation: &PackageRemediation{
			Status: PackageRemediationUnknown,
		},
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if strings.Contains(string(data), `"recommended_version"`) {
		t.Fatalf("Marshal() included empty recommended version: %s", data)
	}
}

func TestPackageRemediationKeepsProtocolV1PackageJSONCompatible(t *testing.T) {
	legacy := []byte(`{
		"purl":"pkg:npm/example@1.0.0",
		"name":"example",
		"version":"1.0.0",
		"vulnerabilities":[{"id":"GHSA-example","fixed_in":"1.2.0"}]
	}`)
	var pkg Package
	if err := json.Unmarshal(legacy, &pkg); err != nil {
		t.Fatalf("Unmarshal(legacy package) error = %v", err)
	}
	if pkg.Remediation != nil {
		t.Fatalf("legacy package unexpectedly gained remediation: %#v", pkg.Remediation)
	}

	pkg.Remediation = &PackageRemediation{
		Status:             PackageRemediationComplete,
		RecommendedVersion: "1.2.0",
	}
	current, err := json.Marshal(pkg)
	if err != nil {
		t.Fatalf("Marshal(current package) error = %v", err)
	}
	var roundTrip Package
	if err := json.Unmarshal(current, &roundTrip); err != nil {
		t.Fatalf("Unmarshal(current package) error = %v", err)
	}
	if roundTrip.Remediation == nil ||
		roundTrip.Remediation.Status != PackageRemediationComplete ||
		roundTrip.Remediation.RecommendedVersion != "1.2.0" {
		t.Fatalf("current remediation did not round trip: %#v", roundTrip.Remediation)
	}
}
