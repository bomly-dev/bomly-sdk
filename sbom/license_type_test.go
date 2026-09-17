package sbom

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/spdxkit"
	testkit "github.com/bomly-dev/bomly-sdk/testkit"
)

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

// FuzzLicenseTypes drives both codecs with two licenses of arbitrary value and
// kind. Whatever arrives, each SPDX field holds only something SPDX can hold
// and only its own kind of claim, every minted reference is named by a field,
// no CycloneDX version receives a shape or a field its schema lacks, and
// reading each rendering back recovers the kinds that were written. It is also
// the first fuzz coverage of the SPDX license decoder.
func FuzzLicenseTypes(f *testing.F) {
	for _, seed := range []struct {
		a, b  string
		kinds uint8
	}{
		{"MIT", "Apache-2.0", 0x21},
		{"MIT OR Apache-2.0", "ISC", 0x12},
		{"see LICENSE file", "MIT", 0x22},
		{"LicenseRef-vendor", "(((", 0x10},
		{"", "NOASSERTION", 0x02},
		{"MIT", "MIT", 0x21},
		{"GPL-2.0+", "LGPL-2.1-only WITH Classpath-exception-2.0", 0x03},
	} {
		f.Add(seed.a, seed.b, seed.kinds)
	}
	kindOf := func(bits uint8) string {
		switch bits % 4 {
		case 1:
			return string(model.LicenseTypeDeclared)
		case 2:
			return string(model.LicenseTypeConcluded)
		case 3:
			return "invented"
		default:
			return ""
		}
	}
	f.Fuzz(func(t *testing.T, a, b string, kinds uint8) {
		if len(a)+len(b) > testkit.MaxFuzzInputSize {
			return
		}
		licenses := []License{{Value: a, Type: kindOf(kinds)}, {SPDXExpression: b, Type: kindOf(kinds >> 4)}}

		var hasDeclared, hasConcluded bool
		wantTypes := map[string]bool{}
		for _, license := range licenses {
			if licenseExpressionValue(license) == "" {
				continue
			}
			kind := ""
			if acknowledgement, ok := cycloneDXAcknowledgement(license.Type); ok {
				kind = licenseTypeFromCycloneDX(acknowledgement)
			}
			wantTypes[kind] = true
			if kind == string(model.LicenseTypeConcluded) {
				hasConcluded = true
			} else {
				hasDeclared = true
			}
		}

		declared, concluded, extracted := spdxLicenseFields(licenses)
		for name, field := range map[string]string{"licenseDeclared": declared, "licenseConcluded": concluded} {
			if field != "NOASSERTION" && !spdxkit.Valid(field) {
				t.Fatalf("%s %q does not parse as an SPDX expression", name, field)
			}
		}
		if (declared != "NOASSERTION") != hasDeclared {
			t.Fatalf("licenseDeclared = %q, but a declared or untyped claim present = %v", declared, hasDeclared)
		}
		if (concluded != "NOASSERTION") != hasConcluded {
			t.Fatalf("licenseConcluded = %q, but a concluded claim present = %v", concluded, hasConcluded)
		}
		byRef := map[string]string{}
		for _, entry := range extracted {
			if !strings.Contains(declared, entry.RefID) && !strings.Contains(concluded, entry.RefID) {
				t.Fatalf("minted reference %q is named by neither field", entry.RefID)
			}
			byRef[entry.RefID] = entry.Text
		}
		for _, license := range parseSPDXLicenses(byRef, declared, concluded) {
			if license.Type != string(model.LicenseTypeDeclared) && license.Type != string(model.LicenseTypeConcluded) {
				t.Fatalf("SPDX decode produced an untyped claim %+v", license)
			}
			if license.Type == string(model.LicenseTypeConcluded) && !hasConcluded {
				t.Fatalf("SPDX decode found a concluded claim nobody made: %+v", license)
			}
		}

		for _, specVersion := range []cdx.SpecVersion{cdx.SpecVersion1_4, cdx.SpecVersion1_5, cdx.SpecVersion1_6, cdx.SpecVersion1_7} {
			rendered := cycloneDXLicenses(licenses, specVersion)
			if (len(rendered) > 0) != (len(wantTypes) > 0) {
				t.Fatalf("%v: rendered %d entries from %d kinds of claim", specVersion, len(rendered), len(wantTypes))
			}
			if specVersion < cdx.SpecVersion1_7 && !singleShapeLicenseChoices(rendered) {
				t.Fatalf("%v: rendering mixes shapes: %+v", specVersion, rendered)
			}
			for _, choice := range rendered {
				var acknowledgements []cdx.LicenseAcknowledgement
				if choice.Acknowledgement != nil {
					acknowledgements = append(acknowledgements, *choice.Acknowledgement)
				}
				if choice.License != nil && choice.License.Acknowledgement != "" {
					acknowledgements = append(acknowledgements, choice.License.Acknowledgement)
				}
				for _, acknowledgement := range acknowledgements {
					if specVersion < cdx.SpecVersion1_6 {
						t.Fatalf("%v: acknowledgement %q written where no schema defines it", specVersion, acknowledgement)
					}
					if licenseTypeFromCycloneDX(acknowledgement) == "" {
						t.Fatalf("%v: acknowledgement %q is outside the specification's vocabulary", specVersion, acknowledgement)
					}
				}
			}
			if specVersion == cdx.SpecVersion1_7 {
				// 1.7 always keeps the kinds apart, so reading it back must
				// recover exactly the kinds that went in.
				gotTypes := map[string]bool{}
				for _, license := range parseCycloneDXLicenses(&rendered) {
					gotTypes[license.Type] = true
				}
				if len(gotTypes) != len(wantTypes) {
					t.Fatalf("1.7 read back kinds %v, want %v", gotTypes, wantTypes)
				}
				for kind := range wantTypes {
					if !gotTypes[kind] {
						t.Fatalf("1.7 read back kinds %v, want %v", gotTypes, wantTypes)
					}
				}
			}
		}
	})
}
