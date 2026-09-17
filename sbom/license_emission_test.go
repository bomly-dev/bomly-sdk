package sbom

import (
	"bytes"
	"encoding/json"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bomly-dev/bomly-sdk/internal/testnodes"
	"github.com/bomly-dev/bomly-sdk/spdxkit"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"

	"github.com/bomly-dev/bomly-sdk/model"
)

// licensedGraph builds a one-node graph whose single component declares the
// given licenses at detection time.
func licensedGraph(t *testing.T, licenses ...model.PackageLicense) *model.Graph {
	t.Helper()
	g := model.New()
	dep := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{
		Name:      "left-pad",
		Version:   "1.3.0",
		PURL:      "pkg:npm/left-pad@1.3.0",
		Ecosystem: "npm",
	}})
	model.SetDetectionLicenses(dep, licenses)
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("add node: %v", err)
	}
	return g
}

func cycloneDXComponentLicenses(t *testing.T, g *model.Graph) cdx.Licenses {
	t.Helper()
	out, err := MarshalDepGraphJSON(g, TargetCycloneDX16JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal cyclonedx: %v", err)
	}
	bom := new(cdx.BOM)
	if err := cdx.NewBOMDecoder(bytes.NewReader(out), cdx.BOMFileFormatJSON).Decode(bom); err != nil {
		t.Fatalf("decode cyclonedx: %v", err)
	}
	if bom.Components == nil || len(*bom.Components) != 1 {
		t.Fatalf("expected exactly 1 component, got %#v", bom.Components)
	}
	comp := (*bom.Components)[0]
	if comp.Licenses == nil {
		return nil
	}
	return *comp.Licenses
}

func spdxPackageLicense(t *testing.T, g *model.Graph) *v23.Package {
	t.Helper()
	out, err := MarshalDepGraphJSON(g, TargetSPDX23JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}
	var doc v23.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("decode spdx: %v", err)
	}
	if len(doc.Packages) != 1 {
		t.Fatalf("expected exactly 1 package, got %d", len(doc.Packages))
	}
	return doc.Packages[0]
}

// TestCycloneDXLicenseShapes pins how each kind of license value is published.
// A recognized identifier must reach `license.id` (a checked SPDX list entry),
// a compound value must reach `expression`, and only genuinely unrecognized
// text may fall through to the free-text `license.name`.
func TestCycloneDXLicenseShapes(t *testing.T) {
	tests := []struct {
		name       string
		licenses   []model.PackageLicense
		wantID     string
		wantExpr   string
		wantName   string
		wantLength int
	}{
		{
			name:       "plain identifier becomes license.id",
			licenses:   []model.PackageLicense{{Value: "MIT"}},
			wantID:     "MIT",
			wantLength: 1,
		},
		{
			name:       "identifier casing is canonicalized",
			licenses:   []model.PackageLicense{{Value: "mit"}},
			wantID:     "MIT",
			wantLength: 1,
		},
		{
			name:       "compound value stays an expression",
			licenses:   []model.PackageLicense{{SPDXExpression: "MIT OR Apache-2.0"}},
			wantExpr:   "MIT OR Apache-2.0",
			wantLength: 1,
		},
		{
			name:       "or-later operator stays an expression",
			licenses:   []model.PackageLicense{{SPDXExpression: "LGPL-2.1-only+"}},
			wantExpr:   "LGPL-2.1-only+",
			wantLength: 1,
		},
		{
			name:       "unrecognized text stays free text",
			licenses:   []model.PackageLicense{{Value: "see LICENSE file"}},
			wantName:   "see LICENSE file",
			wantLength: 1,
		},
		{
			// Registry sources write free text into the same field they write
			// real expressions into. Publishing it as `expression` produced a
			// document that fails CycloneDX expression validation.
			name:       "unrecognized expression is demoted to free text",
			licenses:   []model.PackageLicense{{Value: "non-standard", SPDXExpression: "non-standard"}},
			wantName:   "non-standard",
			wantLength: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			licenses := cycloneDXComponentLicenses(t, licensedGraph(t, tc.licenses...))
			if len(licenses) != tc.wantLength {
				t.Fatalf("expected %d license entries, got %#v", tc.wantLength, licenses)
			}
			got := licenses[0]
			switch {
			case tc.wantID != "":
				if got.License == nil || got.License.ID != tc.wantID {
					t.Fatalf("expected license.id %q, got %#v", tc.wantID, got)
				}
				if got.License.Name != "" {
					t.Fatalf("expected no free-text name alongside an id, got %q", got.License.Name)
				}
			case tc.wantExpr != "":
				if got.Expression != tc.wantExpr {
					t.Fatalf("expected expression %q, got %#v", tc.wantExpr, got)
				}
			case tc.wantName != "":
				if got.License == nil || got.License.Name != tc.wantName {
					t.Fatalf("expected license.name %q, got %#v", tc.wantName, got)
				}
				if got.License.ID != "" {
					t.Fatalf("expected no id for unrecognized text, got %q", got.License.ID)
				}
				if got.Expression != "" {
					t.Fatalf("expected no expression for unrecognized text, got %q", got.Expression)
				}
			}
		})
	}
}

// TestCycloneDXMultipleLicenses covers the format's either/or rule: a license
// list holds license objects or one expression, never a mix and never two
// expressions.
func TestCycloneDXMultipleLicenses(t *testing.T) {
	// Listing several licenses says only that they were found. Composing them
	// with AND would claim a package offered under either is bound by both.
	t.Run("several identifiers are listed, not composed", func(t *testing.T) {
		licenses := cycloneDXComponentLicenses(t, licensedGraph(t,
			model.PackageLicense{Value: "MIT"},
			model.PackageLicense{Value: "Apache-2.0"},
		))
		if len(licenses) != 2 {
			t.Fatalf("expected 2 license entries, got %#v", licenses)
		}
		for i, want := range []string{"MIT", "Apache-2.0"} {
			if licenses[i].License == nil || licenses[i].License.ID != want {
				t.Fatalf("expected license.id %q at %d, got %#v", want, i, licenses[i])
			}
			if licenses[i].Expression != "" {
				t.Fatalf("expected no asserted relationship, got %q", licenses[i].Expression)
			}
		}
	})

	// A list cannot mix objects with an expression, and an object cannot hold
	// one, so a compound member leaves composition as the only way to keep it.
	t.Run("a compound member forces composition", func(t *testing.T) {
		licenses := cycloneDXComponentLicenses(t, licensedGraph(t,
			model.PackageLicense{SPDXExpression: "Apache-2.0 OR MIT"},
			model.PackageLicense{Value: "Unicode-DFS-2016"},
		))
		if len(licenses) != 1 {
			t.Fatalf("expected a single composed entry, got %#v", licenses)
		}
		if licenses[0].Expression != "(Apache-2.0 OR MIT) AND Unicode-DFS-2016" {
			t.Fatalf("expected the compound member preserved, got %#v", licenses[0])
		}
	})

	t.Run("mixed validity falls back to per-license objects", func(t *testing.T) {
		licenses := cycloneDXComponentLicenses(t, licensedGraph(t,
			model.PackageLicense{Value: "MIT"},
			model.PackageLicense{Value: "non-standard"},
		))
		if len(licenses) != 2 {
			t.Fatalf("expected 2 license entries, got %#v", licenses)
		}
		if licenses[0].License == nil || licenses[0].License.ID != "MIT" {
			t.Fatalf("expected the recognized license to keep its id, got %#v", licenses[0])
		}
		if licenses[1].License == nil || licenses[1].License.Name != "non-standard" {
			t.Fatalf("expected the unrecognized license as free text, got %#v", licenses[1])
		}
		for _, l := range licenses {
			if l.Expression != "" {
				t.Fatalf("expected no expression when emitting license objects, got %#v", l)
			}
		}
	})
}

// TestSPDXLicenseComposition covers SPDX 2.3 holding one expression per
// package: several declared licenses must compose rather than lose all but the
// first.
func TestSPDXLicenseComposition(t *testing.T) {
	tests := []struct {
		name     string
		licenses []model.PackageLicense
		want     string
	}{
		{
			name: "no licenses",
			want: "NOASSERTION",
		},
		{
			name:     "single value passes through",
			licenses: []model.PackageLicense{{Value: "MIT"}},
			want:     "MIT",
		},
		{
			name: "multiple licenses compose with AND",
			licenses: []model.PackageLicense{
				{Value: "MIT"},
				{Value: "Apache-2.0"},
			},
			want: "MIT AND Apache-2.0",
		},
		{
			name: "compound elements are parenthesized",
			licenses: []model.PackageLicense{
				{Value: "MIT"},
				{SPDXExpression: "MIT OR GPL-2.0-only"},
			},
			want: "MIT AND (MIT OR GPL-2.0-only)",
		},
		{
			// A mixed set composes fully now (#410). The unrecognized member
			// becomes a reference, which is a valid expression element, so
			// nothing is dropped -- this used to keep "MIT" alone and lose
			// the fact that a second license was declared at all.
			name: "an unrecognized member composes as a reference",
			licenses: []model.PackageLicense{
				{Value: "MIT"},
				{Value: "non-standard"},
			},
			want: "MIT AND " + spdxkit.MintLicenseRef("non-standard").RefID,
		},
		{
			// A lone unrecognized value is a reference rather than free text
			// in a field SPDX says must hold an expression.
			name: "a single unrecognized value becomes a reference",
			licenses: []model.PackageLicense{
				{Value: "see LICENSE file"},
			},
			want: spdxkit.MintLicenseRef("see LICENSE file").RefID,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkg := spdxPackageLicense(t, licensedGraph(t, tc.licenses...))
			if pkg.PackageLicenseDeclared != tc.want {
				t.Fatalf("declared: expected %q, got %q", tc.want, pkg.PackageLicenseDeclared)
			}
		})
	}
}

// TestSPDXLicenseFieldsSeparateDeclaredFromConcluded pins where each kind of
// claim is published (#90). SPDX 2.3's Concluded License (7.13) is a
// determination and its Declared License (7.15) is what the package's authors
// said, so a concluded claim must not be published as declared. A claim with
// no type is what a lockfile or registry says, so it stays declared, and a
// package with no concluded claim renders exactly as before: concluded is
// NOASSERTION, SPDX's value for "no determination was made".
func TestSPDXLicenseFieldsSeparateDeclaredFromConcluded(t *testing.T) {
	declared := model.LicenseTypeDeclared
	concluded := model.LicenseTypeConcluded
	for _, tc := range []struct {
		name          string
		licenses      []model.PackageLicense
		wantDeclared  string
		wantConcluded string
	}{
		{"nothing", nil, "NOASSERTION", "NOASSERTION"},
		{"untyped", []model.PackageLicense{{Value: "MIT"}}, "MIT", "NOASSERTION"},
		{"untyped expression", []model.PackageLicense{{SPDXExpression: "MIT OR Apache-2.0"}}, "MIT OR Apache-2.0", "NOASSERTION"},
		{"untyped pair", []model.PackageLicense{{Value: "MIT"}, {Value: "Apache-2.0"}}, "MIT AND Apache-2.0", "NOASSERTION"},
		{"untyped free text", []model.PackageLicense{{Value: "see LICENSE file"}}, spdxkit.MintLicenseRef("see LICENSE file").RefID, "NOASSERTION"},
		{"declared", []model.PackageLicense{{Value: "MIT", Type: declared}}, "MIT", "NOASSERTION"},
		{"concluded only", []model.PackageLicense{{Value: "MIT", Type: concluded}}, "NOASSERTION", "MIT"},
		{
			"one of each",
			[]model.PackageLicense{{Value: "MIT", Type: declared}, {Value: "Apache-2.0", Type: concluded}},
			"MIT", "Apache-2.0",
		},
		{
			"untyped joins declared",
			[]model.PackageLicense{{Value: "MIT"}, {Value: "BSD-3-Clause", Type: declared}, {Value: "Apache-2.0", Type: concluded}},
			"MIT AND BSD-3-Clause", "Apache-2.0",
		},
		{
			"each kind composes on its own",
			[]model.PackageLicense{
				{Value: "MIT", Type: concluded},
				{SPDXExpression: "GPL-2.0-only OR MIT", Type: concluded},
				{Value: "ISC", Type: declared},
			},
			"ISC", "MIT AND (GPL-2.0-only OR MIT)",
		},
		{
			"the same license of both kinds",
			[]model.PackageLicense{{Value: "MIT", Type: declared}, {Value: "MIT", Type: concluded}},
			"MIT", "MIT",
		},
		{
			"concluded free text",
			[]model.PackageLicense{{Value: "Acme terms", Type: concluded}},
			"NOASSERTION", spdxkit.MintLicenseRef("Acme terms").RefID,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkg := spdxPackageLicense(t, licensedGraph(t, tc.licenses...))
			if pkg.PackageLicenseDeclared != tc.wantDeclared {
				t.Errorf("licenseDeclared = %q, want %q", pkg.PackageLicenseDeclared, tc.wantDeclared)
			}
			if pkg.PackageLicenseConcluded != tc.wantConcluded {
				t.Errorf("licenseConcluded = %q, want %q", pkg.PackageLicenseConcluded, tc.wantConcluded)
			}
		})
	}
}

// A reference minted for concluded free text needs its text in the document as
// much as a declared one does, or the citation dangles.
func TestSPDXConcludedReferenceCarriesItsText(t *testing.T) {
	out, err := MarshalDepGraphJSON(licensedGraph(t,
		model.PackageLicense{Value: "Acme terms", Type: model.LicenseTypeConcluded},
		model.PackageLicense{Value: "Other terms", Type: model.LicenseTypeDeclared},
	), TargetSPDX23JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}
	var doc v23.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("decode spdx: %v", err)
	}
	texts := map[string]string{}
	for _, other := range doc.OtherLicenses {
		texts[other.LicenseIdentifier] = other.ExtractedText
	}
	for text, field := range map[string]string{
		"Acme terms":  doc.Packages[0].PackageLicenseConcluded,
		"Other terms": doc.Packages[0].PackageLicenseDeclared,
	} {
		if got, ok := texts[field]; !ok || got != text {
			t.Fatalf("reference %q resolves to %q (present=%v), want %q", field, got, ok, text)
		}
	}
}

// Reading a document back keeps both claims and the kind of each (#90).
// Taking only the first non-empty field dropped the other claim and lost the
// provenance of the one it kept.
func TestSPDXIngestReadsBothLicenseFields(t *testing.T) {
	for _, tc := range []struct {
		name      string
		declared  string
		concluded string
		want      []License
	}{
		{"both", "MIT", "Apache-2.0", []License{
			{Value: "MIT", SPDXExpression: "MIT", Type: "declared"},
			{Value: "Apache-2.0", SPDXExpression: "Apache-2.0", Type: "concluded"},
		}},
		{"the same license in both", "MIT", "MIT", []License{
			{Value: "MIT", SPDXExpression: "MIT", Type: "declared"},
			{Value: "MIT", SPDXExpression: "MIT", Type: "concluded"},
		}},
		{"declared only", "MIT", "NOASSERTION", []License{{Value: "MIT", SPDXExpression: "MIT", Type: "declared"}}},
		{"concluded only", "NONE", "MIT", []License{{Value: "MIT", SPDXExpression: "MIT", Type: "concluded"}}},
		{"neither", "NOASSERTION", "NONE", nil},
		{"fields absent", "", "", nil},
		{"referenced text", "LicenseRef-vendor", "MIT", []License{
			{Value: "vendor terms", SPDXExpression: "LicenseRef-vendor", Type: "declared"},
			{Value: "MIT", SPDXExpression: "MIT", Type: "concluded"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := `{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT",` +
				`"name":"foreign","documentNamespace":"https://example.test/foreign",` +
				`"creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: other"]},` +
				`"hasExtractedLicensingInfos":[{"licenseId":"LicenseRef-vendor","extractedText":"vendor terms"}],` +
				`"packages":[{"SPDXID":"SPDXRef-a","name":"a","versionInfo":"1.0.0","downloadLocation":"NOASSERTION",` +
				`"licenseDeclared":"` + tc.declared + `","licenseConcluded":"` + tc.concluded + `",` +
				`"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:npm/a@1.0.0"}]}]}`
			doc, _, err := UnmarshalAutoJSON([]byte(raw))
			if err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			got := doc.Components[0].Licenses
			if len(got) != len(tc.want) {
				t.Fatalf("licenses = %#v, want %#v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("license %d = %#v, want %#v", i, got[i], tc.want[i])
				}
			}

			// And through to the graph, where the merge must keep a declared
			// and a concluded claim of one license as two claims.
			g, err := ToGraph(doc)
			if err != nil {
				t.Fatalf("to graph: %v", err)
			}
			nodeLicenses := model.DetectionLicenses(g.DependencyNodes()[0])
			if len(nodeLicenses) != len(tc.want) {
				t.Fatalf("node licenses = %#v, want %d claims", nodeLicenses, len(tc.want))
			}
			for i, license := range nodeLicenses {
				if string(license.Type) != tc.want[i].Type {
					t.Fatalf("node license %d type = %q, want %q", i, license.Type, tc.want[i].Type)
				}
			}
		})
	}
}

// TestSPDXConcludedNoAssertionSurvivesIngest covers the round trip: a document
// whose concluded field is NOASSERTION must still yield the declared license
// when read back, not a literal "NOASSERTION" license.
func TestSPDXConcludedNoAssertionSurvivesIngest(t *testing.T) {
	out, err := MarshalDepGraphJSON(licensedGraph(t, model.PackageLicense{Value: "MIT"}),
		TargetSPDX23JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}
	doc, _, err := UnmarshalAutoJSON(out)
	if err != nil {
		t.Fatalf("unmarshal document: %v", err)
	}
	if len(doc.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(doc.Components))
	}
	licenses := doc.Components[0].Licenses
	if len(licenses) != 1 || licenses[0].Value != "MIT" {
		t.Fatalf("expected the declared MIT license to survive ingest, got %#v", licenses)
	}
}

// TestSourceStatedRelationshipSurvivesBothFormats covers the case that
// actually matters for dual licensing: when a source states the relationship
// itself ("Apache-2.0 OR MIT", how registries record it), both formats publish
// that expression unchanged rather than reinterpreting it.
func TestSourceStatedRelationshipSurvivesBothFormats(t *testing.T) {
	const expression = "Apache-2.0 OR MIT"
	licenses := []model.PackageLicense{{SPDXExpression: expression}}

	cdxLicenses := cycloneDXComponentLicenses(t, licensedGraph(t, licenses...))
	if len(cdxLicenses) != 1 || cdxLicenses[0].Expression != expression {
		t.Fatalf("cyclonedx changed a source-stated expression: %#v", cdxLicenses)
	}
	if got := spdxPackageLicense(t, licensedGraph(t, licenses...)).PackageLicenseDeclared; got != expression {
		t.Fatalf("spdx changed a source-stated expression: %q", got)
	}
}

// TestMultipleLicensesDivergeByFormat pins the one deliberate cross-format
// difference. CycloneDX can list licenses without relating them; SPDX 2.3
// holds a single expression and has no such form, so it must compose. Both are
// the most faithful thing each format can say.
func TestMultipleLicensesDivergeByFormat(t *testing.T) {
	licenses := []model.PackageLicense{{Value: "MIT"}, {Value: "Apache-2.0"}}

	cdxLicenses := cycloneDXComponentLicenses(t, licensedGraph(t, licenses...))
	if len(cdxLicenses) != 2 {
		t.Fatalf("expected CycloneDX to list both licenses, got %#v", cdxLicenses)
	}
	if got := spdxPackageLicense(t, licensedGraph(t, licenses...)).PackageLicenseDeclared; got != "MIT AND Apache-2.0" {
		t.Fatalf("expected SPDX to compose, got %q", got)
	}
}

// A license expression is emitted in its canonical spelling, not the source's.
//
// The SDK accepts an expression whose operators and identifiers are cased
// freely, so "LGPL-2.0 WiTH ClAsspAth-eXCeptIon-2.0" classifies as a valid
// expression. The SPDX field it lands in is read as a strict expression
// though, so passing the source's spelling through wrote a document consumers
// cannot parse -- and composing two such values produced a field that failed
// even the SDK's own check. Found by FuzzSPDXLicenseValue.
func TestLicenseExpressionsAreEmittedCanonically(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		given []License
		want  string
	}{
		{
			name:  "operator and identifier casing",
			given: []License{{SPDXExpression: "LGPL-2.0 WiTH ClAsspAth-eXCeptIon-2.0"}},
			want:  "LGPL-2.0-only WITH Classpath-exception-2.0",
		},
		{
			name: "composed values are each canonical",
			given: []License{
				{SPDXExpression: "mIt"},
				{SPDXExpression: "LGPL-2.0 WiTH ClAsspAth-eXCeptIon-2.0"},
			},
			want: "MIT AND LGPL-2.0-only WITH Classpath-exception-2.0",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got, _ := spdxLicenseValue(testCase.given)
			if !spdxkit.Valid(got) {
				t.Fatalf("emitted %q, which does not parse as an SPDX expression", got)
			}
			if got != testCase.want {
				t.Errorf("emitted %q, want %q", got, testCase.want)
			}
		})
	}
}

// Every algorithm the SDK knows an SPDX spelling for must survive export.
//
// This is a differential test on purpose. Referencing constants makes a rename
// a compile error and does nothing about an addition, which is exactly how a
// hand-written switch here came to know nine algorithms against the registry's
// nineteen -- dropping BLAKE2b, BLAKE3, MD2, MD4, MD6, ADLER32 and Streebog
// checksums on export without a word. Reading the registry means the next
// algorithm added upstream fails this test rather than disappearing.
func TestEverySPDXKnownDigestAlgorithmIsEmitted(t *testing.T) {
	var checked int
	for _, algorithm := range model.DigestAlgorithms() {
		spdxName := algorithm.SPDXName()
		if spdxName == "" {
			continue // SPDX does not define this one; the format's limit, not ours.
		}
		checked++
		got := spdxChecksumAlgorithm(string(algorithm))
		if string(got) != spdxName {
			t.Errorf("%s renders as %q, want SPDX's %q", algorithm, got, spdxName)
		}
	}
	if checked < 10 {
		t.Fatalf("only %d algorithms were checked; the registry looks unread", checked)
	}
}

// Every algorithm the SDK knows a CycloneDX spelling for must survive export,
// and must go out in that spelling.
//
// The mirror of TestEverySPDXKnownDigestAlgorithmIsEmitted, and it exists for
// the same reason twice over: a hand-written switch here knew eight algorithms
// against the registry's nineteen, and the external-reference path cast the
// SDK token straight into the enum, writing "sha256" where the schema says
// "SHA-256". Differential on purpose -- a constant reference makes a rename a
// compile error and says nothing about an addition.
func TestEveryCycloneDXKnownDigestAlgorithmIsEmitted(t *testing.T) {
	var checked int
	for _, algorithm := range model.DigestAlgorithms() {
		name := algorithm.CycloneDXName()
		if name == "" {
			continue // CycloneDX does not define this one; the format's limit.
		}
		checked++
		if got := cycloneDXHashAlgorithm(string(algorithm)); string(got) != name {
			t.Errorf("%s renders as %q, want CycloneDX's %q", algorithm, got, name)
		}
	}
	if checked < 10 {
		t.Fatalf("only %d algorithms were checked; the registry looks unread", checked)
	}
}

// An algorithm CycloneDX has no name for is omitted rather than written in a
// spelling the schema rejects.
func TestUnmappableDigestIsOmittedFromCycloneDXReferences(t *testing.T) {
	hashes := cycloneDXEmittedHashes([]model.Digest{
		{Algorithm: model.DigestAlgorithmADLER32, Value: "0badf00d"},
		{Algorithm: model.DigestAlgorithmSHA256, Value: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
	})
	if hashes == nil {
		t.Fatal("the sha-256 hash was dropped along with the unmappable one")
	}
	for _, h := range *hashes {
		if h.Algorithm == "adler32" || h.Algorithm == "ADLER32" {
			t.Errorf("an algorithm CycloneDX does not define was emitted: %+v", h)
		}
		if h.Algorithm == "sha256" {
			t.Errorf("the SDK token was emitted instead of CycloneDX's spelling: %+v", h)
		}
	}
}
