package sbom

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
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

var cycloneDXTargets = []struct {
	target  Target
	version cdx.SpecVersion
}{
	{TargetCycloneDX14JSON, cdx.SpecVersion1_4},
	{TargetCycloneDX15JSON, cdx.SpecVersion1_5},
	{TargetCycloneDX16JSON, cdx.SpecVersion1_6},
	{TargetCycloneDX17JSON, cdx.SpecVersion1_7},
}

// cycloneDXLicensesAt encodes g at target and returns the single component's
// licenses together with the raw document.
func cycloneDXLicensesAt(t *testing.T, g *model.Graph, target Target) (cdx.Licenses, []byte) {
	t.Helper()
	out, err := MarshalDepGraphJSON(g, target, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal %s: %v", target, err)
	}
	bom := new(cdx.BOM)
	if err := cdx.NewBOMDecoder(bytes.NewReader(out), cdx.BOMFileFormatJSON).Decode(bom); err != nil {
		t.Fatalf("decode %s: %v", target, err)
	}
	if bom.Components == nil || len(*bom.Components) != 1 {
		t.Fatalf("%s: expected exactly 1 component, got %#v", target, bom.Components)
	}
	comp := (*bom.Components)[0]
	if comp.Licenses == nil {
		return nil, out
	}
	return *comp.Licenses, out
}

// renderedLicense is one published license entry, flattened for comparison.
type renderedLicense struct {
	value           string
	expression      bool
	acknowledgement cdx.LicenseAcknowledgement
}

func flattenCycloneDXLicenses(licenses cdx.Licenses) []renderedLicense {
	out := make([]renderedLicense, 0, len(licenses))
	for _, choice := range licenses {
		switch {
		case choice.Expression != "":
			entry := renderedLicense{value: choice.Expression, expression: true}
			if choice.Acknowledgement != nil {
				entry.acknowledgement = *choice.Acknowledgement
			}
			out = append(out, entry)
		case choice.License != nil:
			value := choice.License.ID
			if value == "" {
				value = choice.License.Name
			}
			out = append(out, renderedLicense{value: value, acknowledgement: choice.License.Acknowledgement})
		}
	}
	return out
}

// TestCycloneDXLicenseAcknowledgement pins how each kind of claim is published
// at each specification version (#90).
func TestCycloneDXLicenseAcknowledgement(t *testing.T) {
	declared, concluded := model.LicenseTypeDeclared, model.LicenseTypeConcluded
	ackDeclared, ackConcluded := cdx.LicenseAcknowledgementDeclared, cdx.LicenseAcknowledgementConcluded

	for _, tc := range []struct {
		name     string
		licenses []model.PackageLicense
		// want is the rendering from 1.6 on, and pre16 the rendering before
		// it, where no acknowledgement exists. want17 overrides want for 1.7
		// when the two differ.
		want, want17, pre16 []renderedLicense
	}{
		{
			name:     "untyped carries no acknowledgement",
			licenses: []model.PackageLicense{{Value: "MIT"}},
			want:     []renderedLicense{{value: "MIT"}},
			pre16:    []renderedLicense{{value: "MIT"}},
		},
		{
			name:     "declared",
			licenses: []model.PackageLicense{{Value: "MIT", Type: declared}},
			want:     []renderedLicense{{value: "MIT", acknowledgement: ackDeclared}},
			pre16:    []renderedLicense{{value: "MIT"}},
		},
		{
			name:     "concluded expression",
			licenses: []model.PackageLicense{{SPDXExpression: "MIT OR Apache-2.0", Type: concluded}},
			want:     []renderedLicense{{value: "MIT OR Apache-2.0", expression: true, acknowledgement: ackConcluded}},
			pre16:    []renderedLicense{{value: "MIT OR Apache-2.0", expression: true}},
		},
		{
			name:     "one of each, as license objects",
			licenses: []model.PackageLicense{{Value: "MIT", Type: declared}, {Value: "Apache-2.0", Type: concluded}},
			want: []renderedLicense{
				{value: "MIT", acknowledgement: ackDeclared},
				{value: "Apache-2.0", acknowledgement: ackConcluded},
			},
			pre16: []renderedLicense{{value: "MIT"}, {value: "Apache-2.0"}},
		},
		{
			name:     "untyped beside typed is listed without a claim",
			licenses: []model.PackageLicense{{Value: "ISC"}, {Value: "MIT", Type: concluded}},
			want: []renderedLicense{
				{value: "ISC"},
				{value: "MIT", acknowledgement: ackConcluded},
			},
			pre16: []renderedLicense{{value: "ISC"}, {value: "MIT"}},
		},
		{
			name: "free text keeps its kind",
			licenses: []model.PackageLicense{
				{Value: "see LICENSE file", Type: declared},
				{Value: "MIT", Type: concluded},
			},
			want: []renderedLicense{
				{value: "see LICENSE file", acknowledgement: ackDeclared},
				{value: "MIT", acknowledgement: ackConcluded},
			},
			pre16: []renderedLicense{{value: "see LICENSE file"}, {value: "MIT"}},
		},
		{
			// 1.6 allows one expression or a list of objects, never both, so
			// an expression beside another claim has no valid typed form. The
			// set renders as it would untyped: nothing dropped, no provenance
			// stated for an expression that mixes both kinds. 1.7 can hold
			// both, each with its own acknowledgement.
			name: "an expression beside another kind",
			licenses: []model.PackageLicense{
				{SPDXExpression: "MIT OR Apache-2.0", Type: declared},
				{Value: "MIT", Type: concluded},
			},
			want: []renderedLicense{{value: "(MIT OR Apache-2.0) AND MIT", expression: true}},
			want17: []renderedLicense{
				{value: "MIT OR Apache-2.0", expression: true, acknowledgement: ackDeclared},
				{value: "MIT", acknowledgement: ackConcluded},
			},
			pre16: []renderedLicense{{value: "(MIT OR Apache-2.0) AND MIT", expression: true}},
		},
		{
			name: "two expressions of different kinds",
			licenses: []model.PackageLicense{
				{SPDXExpression: "MIT OR Apache-2.0", Type: declared},
				{SPDXExpression: "GPL-2.0-only WITH Classpath-exception-2.0", Type: concluded},
			},
			want: []renderedLicense{{value: "(MIT OR Apache-2.0) AND GPL-2.0-only WITH Classpath-exception-2.0", expression: true}},
			want17: []renderedLicense{
				{value: "MIT OR Apache-2.0", expression: true, acknowledgement: ackDeclared},
				{value: "GPL-2.0-only WITH Classpath-exception-2.0", expression: true, acknowledgement: ackConcluded},
			},
			pre16: []renderedLicense{{value: "(MIT OR Apache-2.0) AND GPL-2.0-only WITH Classpath-exception-2.0", expression: true}},
		},
	} {
		for _, target := range cycloneDXTargets {
			t.Run(tc.name+"/"+string(target.target), func(t *testing.T) {
				want := tc.want
				switch {
				case target.version < cdx.SpecVersion1_6:
					want = tc.pre16
				case target.version >= cdx.SpecVersion1_7 && tc.want17 != nil:
					want = tc.want17
				}
				licenses, raw := cycloneDXLicensesAt(t, licensedGraph(t, tc.licenses...), target.target)
				got := flattenCycloneDXLicenses(licenses)
				if len(got) != len(want) {
					t.Fatalf("licenses = %+v, want %+v", got, want)
				}
				for i := range got {
					if got[i] != want[i] {
						t.Fatalf("license %d = %+v, want %+v", i, got[i], want[i])
					}
				}
				// Asserted on the bytes too: cyclonedx-go strips the object
				// form's acknowledgement below 1.6 but not the expression
				// form's, and a decoder reading the document back would not
				// show a field the struct happens to drop.
				if target.version < cdx.SpecVersion1_6 && strings.Contains(string(raw), `"acknowledgement"`) {
					t.Fatalf("%s carries acknowledgement, which its schema does not define:\n%s", target.target, raw)
				}
			})
		}
	}
}

// A single-shape check on its own: 1.6 must never receive the mixed list that
// only 1.7 defines, whatever mix of kinds arrives.
func TestCycloneDX16LicenseListsKeepOneShape(t *testing.T) {
	kinds := []model.LicenseType{"", model.LicenseTypeDeclared, model.LicenseTypeConcluded}
	values := []string{"MIT", "MIT OR Apache-2.0", "see LICENSE file"}
	for _, first := range kinds {
		for _, second := range kinds {
			for _, a := range values {
				for _, b := range values {
					licenses := []License{{Value: a, Type: string(first)}, {Value: b, Type: string(second)}}
					got := cycloneDXLicenses(licenses, cdx.SpecVersion1_6)
					if !singleShapeLicenseChoices(got) {
						t.Fatalf("1.6 rendering of %+v mixes shapes: %+v", licenses, got)
					}
				}
			}
		}
	}
}

// Reading a document back keeps the kind each license states, from where the
// specification puts it, and nothing else.
func TestCycloneDXIngestReadsAcknowledgement(t *testing.T) {
	for _, tc := range []struct {
		name     string
		licenses string
		want     []License
	}{
		{
			"license objects",
			`[{"license":{"id":"MIT","acknowledgement":"declared"}},{"license":{"name":"Acme terms","acknowledgement":"concluded"}}]`,
			[]License{
				{Value: "MIT", SPDXExpression: "MIT", Type: "declared"},
				{Value: "Acme terms", Type: "concluded"},
			},
		},
		{
			"expression",
			`[{"expression":"MIT OR Apache-2.0","acknowledgement":"concluded"}]`,
			[]License{{Value: "MIT OR Apache-2.0", SPDXExpression: "MIT OR Apache-2.0", Type: "concluded"}},
		},
		{
			"no acknowledgement",
			`[{"license":{"id":"MIT"}}]`,
			[]License{{Value: "MIT", SPDXExpression: "MIT"}},
		},
		{
			"a value the specification does not define",
			`[{"license":{"id":"MIT","acknowledgement":"observed"}}]`,
			[]License{{Value: "MIT", SPDXExpression: "MIT"}},
		},
		{
			"mixed list, as 1.7 writes it",
			`[{"expression":"MIT OR Apache-2.0","acknowledgement":"declared"},{"license":{"id":"ISC","acknowledgement":"concluded"}}]`,
			[]License{
				{Value: "MIT OR Apache-2.0", SPDXExpression: "MIT OR Apache-2.0", Type: "declared"},
				{Value: "ISC", SPDXExpression: "ISC", Type: "concluded"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := `{"bomFormat":"CycloneDX","specVersion":"1.7","version":1,` +
				`"components":[{"type":"library","bom-ref":"a","name":"a","version":"1.0.0",` +
				`"purl":"pkg:npm/a@1.0.0","licenses":` + tc.licenses + `}]}`
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
		})
	}
}

// claim is a license reduced to what a round trip must preserve.
type claim struct {
	value       string
	licenseType model.LicenseType
}

func claimsOf(licenses []model.PackageLicense) []claim {
	out := make([]claim, 0, len(licenses))
	for _, license := range licenses {
		value := license.SPDXExpression
		if value == "" {
			value = license.Value
		}
		out = append(out, claim{value: value, licenseType: license.Type})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].value != out[j].value {
			return out[i].value < out[j].value
		}
		return out[i].licenseType < out[j].licenseType
	})
	return out
}

// TestTypedLicensesSurviveEveryHop is the round trip #90 asks for: a declared
// and a concluded license on one package survive SPDX to SPDX, CycloneDX to
// CycloneDX, and each hop between the two.
func TestTypedLicensesSurviveEveryHop(t *testing.T) {
	sets := map[string][]model.PackageLicense{
		"identifiers": {
			{Value: "MIT", SPDXExpression: "MIT", Type: model.LicenseTypeDeclared},
			{Value: "Apache-2.0", SPDXExpression: "Apache-2.0", Type: model.LicenseTypeConcluded},
		},
		"one license of both kinds": {
			{Value: "MIT", SPDXExpression: "MIT", Type: model.LicenseTypeDeclared},
			{Value: "MIT", SPDXExpression: "MIT", Type: model.LicenseTypeConcluded},
		},
	}
	// An expression beside another kind needs 1.7 on the CycloneDX side; SPDX
	// always has a field per kind.
	expressionSet := []model.PackageLicense{
		{Value: "MIT OR Apache-2.0", SPDXExpression: "MIT OR Apache-2.0", Type: model.LicenseTypeDeclared},
		{Value: "ISC", SPDXExpression: "ISC", Type: model.LicenseTypeConcluded},
	}
	targets := []Target{TargetSPDX23JSON, TargetCycloneDX16JSON, TargetCycloneDX17JSON}

	hop := func(t *testing.T, g *model.Graph, target Target) *model.Graph {
		t.Helper()
		out, err := MarshalDepGraphJSON(g, target, BuildOptions{}, EncodeOptions{})
		if err != nil {
			t.Fatalf("marshal %s: %v", target, err)
		}
		doc, _, err := UnmarshalAutoJSON(out)
		if err != nil {
			t.Fatalf("unmarshal %s: %v", target, err)
		}
		next, err := ToGraph(doc)
		if err != nil {
			t.Fatalf("to graph from %s: %v", target, err)
		}
		return next
	}
	check := func(t *testing.T, name string, licenses []model.PackageLicense, first, second Target) {
		t.Run(name+"/"+string(first)+"->"+string(second), func(t *testing.T) {
			g := hop(t, hop(t, licensedGraph(t, licenses...), first), second)
			nodes := g.DependencyNodes()
			if len(nodes) != 1 {
				t.Fatalf("expected 1 node, got %d", len(nodes))
			}
			// Exported once more, to compare what the second hop read.
			final := hop(t, g, second).DependencyNodes()[0]
			want := claimsOf(licenses)
			for label, gotLicenses := range map[string][]model.PackageLicense{
				"after two hops":   model.DetectionLicenses(nodes[0]),
				"after three hops": model.DetectionLicenses(final),
			} {
				got := claimsOf(gotLicenses)
				if len(got) != len(want) {
					t.Fatalf("%s: claims = %+v, want %+v", label, got, want)
				}
				for i := range got {
					if got[i] != want[i] {
						t.Fatalf("%s: claim %d = %+v, want %+v", label, i, got[i], want[i])
					}
				}
			}
		})
	}
	for name, licenses := range sets {
		for _, first := range targets {
			for _, second := range targets {
				check(t, name, licenses, first, second)
			}
		}
	}
	for _, first := range []Target{TargetSPDX23JSON, TargetCycloneDX17JSON} {
		for _, second := range []Target{TargetSPDX23JSON, TargetCycloneDX17JSON} {
			check(t, "an expression beside another kind", expressionSet, first, second)
		}
	}
}

// The acknowledgement mapping is total over the model's vocabulary and refuses
// anything outside it, in both directions.
func TestLicenseAcknowledgementMapping(t *testing.T) {
	for _, licenseType := range []model.LicenseType{model.LicenseTypeDeclared, model.LicenseTypeConcluded} {
		acknowledgement, ok := cycloneDXAcknowledgement(string(licenseType))
		if !ok {
			t.Fatalf("%q has no acknowledgement", licenseType)
		}
		if back := licenseTypeFromCycloneDX(acknowledgement); back != string(licenseType) {
			t.Fatalf("%q maps to %q and back to %q", licenseType, acknowledgement, back)
		}
	}
	for _, value := range []string{"", "observed", "DECLARED ", strings.Repeat("x", 100)} {
		acknowledgement, ok := cycloneDXAcknowledgement(value)
		// The model's gate folds case and space, so "DECLARED " is declared.
		if value == "DECLARED " {
			if !ok || acknowledgement != cdx.LicenseAcknowledgementDeclared {
				t.Fatalf("%q = %q, %v; want the gate's reading, declared", value, acknowledgement, ok)
			}
			continue
		}
		if ok {
			t.Fatalf("%q mapped to %q, want no acknowledgement", value, acknowledgement)
		}
	}
	if got := licenseTypeFromCycloneDX("observed"); got != "" {
		t.Fatalf("an undefined acknowledgement read as %q", got)
	}
}

// The document a 1.6 export produces must still be one the 1.6 schema's
// license shape accepts once encoded, not only in memory.
func TestCycloneDXTypedLicensesEncodeAsValidJSON(t *testing.T) {
	g := licensedGraph(t,
		model.PackageLicense{Value: "MIT", Type: model.LicenseTypeDeclared},
		model.PackageLicense{SPDXExpression: "MIT OR Apache-2.0", Type: model.LicenseTypeConcluded},
	)
	for _, target := range cycloneDXTargets {
		_, raw := cycloneDXLicensesAt(t, g, target.target)
		var generic map[string]any
		if err := json.Unmarshal(raw, &generic); err != nil {
			t.Fatalf("%s: not JSON: %v", target.target, err)
		}
		components := generic["components"].([]any)
		licenses := components[0].(map[string]any)["licenses"].([]any)
		var objects, expressions int
		for _, entry := range licenses {
			entryMap := entry.(map[string]any)
			if _, ok := entryMap["expression"]; ok {
				expressions++
			}
			if _, ok := entryMap["license"]; ok {
				objects++
			}
		}
		if target.version < cdx.SpecVersion1_7 && expressions > 0 && (expressions != 1 || objects != 0) {
			t.Fatalf("%s: %d expressions beside %d objects; the schema allows one expression alone", target.target, expressions, objects)
		}
	}
}

// A spelling go-spdx accepts but cannot render back is not published as an
// expression in either format: SPDX cites it through a minted reference that
// carries the text, and CycloneDX names it as free text.
func TestLenientLicenseSpellingIsPublishedAsFreeText(t *testing.T) {
	const lenient = "APL-1.0+WITHClAsspAth-eXCeption-2.0"
	for _, licenseType := range []model.LicenseType{"", model.LicenseTypeConcluded} {
		g := licensedGraph(t, model.PackageLicense{Value: lenient, SPDXExpression: lenient, Type: licenseType})
		pkg := spdxPackageLicense(t, g)
		field := pkg.PackageLicenseDeclared
		if licenseType == model.LicenseTypeConcluded {
			field = pkg.PackageLicenseConcluded
		}
		if want := spdxkit.MintLicenseRef(lenient).RefID; field != want {
			t.Fatalf("type %q: SPDX field = %q, want the minted reference %q", licenseType, field, want)
		}
		licenses := cycloneDXComponentLicenses(t, g)
		if len(licenses) != 1 || licenses[0].License == nil || licenses[0].License.Name != lenient || licenses[0].Expression != "" {
			t.Fatalf("type %q: CycloneDX licenses = %+v, want the value as a license name", licenseType, licenses)
		}
	}
}
