package sbom

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"

	"github.com/bomly-dev/bomly-sdk/internal/testnodes"
	"github.com/bomly-dev/bomly-sdk/model"
)

// copyrightCases are the values the copyright gate has to decide, with what a
// published document may carry for each. The over-long value is one byte past
// the bound the model documents for descriptions, which copyright shares.
var copyrightCases = []struct {
	name  string
	value string
	want  string
}{
	{"plain notice", "Copyright (c) 2014, Walmart and other contributors.", "Copyright (c) 2014, Walmart and other contributors."},
	{"several holders", "Copyright (c) 2020 Alice\nCopyright (c) 2021 Bob", "Copyright (c) 2020 Alice\nCopyright (c) 2021 Bob"},
	{"control characters", "Copyright\x07 Acme\x1b[0m", "Copyright Acme[0m"},
	{"over-long", strings.Repeat("c", 8*1024+1), ""},
}

func copyrightGraph(t *testing.T, copyright string) *model.Graph {
	t.Helper()
	g := model.New()
	// Set directly on the node, as an in-process producer would: nothing has
	// gated it yet, so the export path is what is under test.
	dep := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{
		Name:      "accept",
		Version:   "1.1.0",
		PURL:      "pkg:npm/accept@1.1.0",
		Ecosystem: "npm",
	}})
	dep.Copyright = copyright
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("add node: %v", err)
	}
	return g
}

// TestExportedCopyrightIsGated pins #89 on the way out: whatever a node holds,
// neither format publishes a copyright the model's gate would refuse.
func TestExportedCopyrightIsGated(t *testing.T) {
	for _, tc := range copyrightCases {
		t.Run(tc.name, func(t *testing.T) {
			g := copyrightGraph(t, tc.value)

			out, err := MarshalDepGraphJSON(g, TargetSPDX23JSON, BuildOptions{}, EncodeOptions{})
			if err != nil {
				t.Fatalf("marshal spdx: %v", err)
			}
			var spdxDoc v23.Document
			if err := json.Unmarshal(out, &spdxDoc); err != nil {
				t.Fatalf("unmarshal spdx: %v", err)
			}
			if len(spdxDoc.Packages) != 1 {
				t.Fatalf("expected 1 package, got %d", len(spdxDoc.Packages))
			}
			if got := spdxDoc.Packages[0].PackageCopyrightText; got != tc.want {
				t.Fatalf("spdx copyrightText = %q, want %q", truncate(got), truncate(tc.want))
			}

			out, err = MarshalDepGraphJSON(g, TargetCycloneDX16JSON, BuildOptions{}, EncodeOptions{})
			if err != nil {
				t.Fatalf("marshal cyclonedx: %v", err)
			}
			bom := new(cdx.BOM)
			if err := cdx.NewBOMDecoder(bytes.NewReader(out), cdx.BOMFileFormatJSON).Decode(bom); err != nil {
				t.Fatalf("decode cyclonedx: %v", err)
			}
			if bom.Components == nil || len(*bom.Components) != 1 {
				t.Fatalf("expected 1 component, got %#v", bom.Components)
			}
			if got := (*bom.Components)[0].Copyright; got != tc.want {
				t.Fatalf("cyclonedx copyright = %q, want %q", truncate(got), truncate(tc.want))
			}
		})
	}
}

// TestIngestedCopyrightIsGated pins #89 on the way in, for a foreign document
// in each format: the decoded component and the graph node both hold only what
// the gate admits, and a second hop changes nothing.
func TestIngestedCopyrightIsGated(t *testing.T) {
	for _, tc := range copyrightCases {
		t.Run(tc.name, func(t *testing.T) {
			quoted, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatalf("quote value: %v", err)
			}
			documents := map[string]string{
				"spdx": `{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT",` +
					`"name":"foreign","documentNamespace":"https://example.test/foreign",` +
					`"creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: other"]},` +
					`"packages":[{"SPDXID":"SPDXRef-accept","name":"accept","versionInfo":"1.1.0",` +
					`"downloadLocation":"NOASSERTION","copyrightText":` + string(quoted) + `,` +
					`"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",` +
					`"referenceLocator":"pkg:npm/accept@1.1.0"}]}]}`,
				"cyclonedx": `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,` +
					`"components":[{"type":"library","bom-ref":"accept","name":"accept","version":"1.1.0",` +
					`"purl":"pkg:npm/accept@1.1.0","copyright":` + string(quoted) + `}]}`,
			}
			for format, raw := range documents {
				doc, _, err := UnmarshalAutoJSON([]byte(raw))
				if err != nil {
					t.Fatalf("%s: unmarshal: %v", format, err)
				}
				if len(doc.Components) != 1 {
					t.Fatalf("%s: expected 1 component, got %d", format, len(doc.Components))
				}
				if got := doc.Components[0].Copyright; got != tc.want {
					t.Fatalf("%s: decoded copyright = %q, want %q", format, truncate(got), truncate(tc.want))
				}
				g, err := ToGraph(doc)
				if err != nil {
					t.Fatalf("%s: to graph: %v", format, err)
				}
				nodes := g.DependencyNodes()
				if len(nodes) != 1 {
					t.Fatalf("%s: expected 1 node, got %d", format, len(nodes))
				}
				if got := nodes[0].Copyright; got != tc.want {
					t.Fatalf("%s: node copyright = %q, want %q", format, truncate(got), truncate(tc.want))
				}
				if again := model.NormalizeCopyright(nodes[0].Copyright); again != nodes[0].Copyright {
					t.Fatalf("%s: stored copyright is not a fixed point of the gate", format)
				}
			}
		})
	}
}

// ToGraph gates a component it is handed directly, not only one a decoder
// produced: a caller can build a Document by hand.
func TestToGraphGatesAHandBuiltComponentCopyright(t *testing.T) {
	doc := &Document{Components: []Component{{
		ID:        "accept",
		Name:      "accept",
		Version:   "1.1.0",
		PURL:      "pkg:npm/accept@1.1.0",
		Copyright: "Copyright\x00 Walmart",
	}}}
	g, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	if got := g.DependencyNodes()[0].Copyright; got != "Copyright Walmart" {
		t.Fatalf("node copyright = %q, want the control character dropped", got)
	}
}

// The export gate is layered: the projection gates the component it builds,
// and each encoder gates what it writes. These two tests hold each layer on
// its own, since the end-to-end test above passes while either one stands.
func TestProjectionGatesCopyright(t *testing.T) {
	for _, tc := range copyrightCases {
		doc, err := FromDepGraph(copyrightGraph(t, tc.value), BuildOptions{})
		if err != nil {
			t.Fatalf("%s: project: %v", tc.name, err)
		}
		var found bool
		for _, component := range doc.Components {
			if component.PURL != "pkg:npm/accept@1.1.0" {
				continue
			}
			found = true
			if component.Copyright != tc.want {
				t.Fatalf("%s: projected copyright = %q, want %q", tc.name, truncate(component.Copyright), truncate(tc.want))
			}
		}
		if !found {
			t.Fatalf("%s: the component was not projected", tc.name)
		}
	}
}

func TestEncodersGateAHandBuiltDocumentCopyright(t *testing.T) {
	for _, tc := range copyrightCases {
		doc := &Document{
			Name:      "hand-built",
			Namespace: "https://example.test/hand-built",
			Components: []Component{{
				ID:        "accept",
				Name:      "accept",
				Version:   "1.1.0",
				PURL:      "pkg:npm/accept@1.1.0",
				Copyright: tc.value,
			}},
			Roots: []string{"accept"},
		}

		out, err := MarshalJSON(doc, TargetSPDX23JSON, EncodeOptions{})
		if err != nil {
			t.Fatalf("%s: marshal spdx: %v", tc.name, err)
		}
		var spdxDoc v23.Document
		if err := json.Unmarshal(out, &spdxDoc); err != nil {
			t.Fatalf("%s: unmarshal spdx: %v", tc.name, err)
		}
		if got := spdxDoc.Packages[0].PackageCopyrightText; got != tc.want {
			t.Fatalf("%s: spdx copyrightText = %q, want %q", tc.name, truncate(got), truncate(tc.want))
		}

		out, err = MarshalJSON(doc, TargetCycloneDX16JSON, EncodeOptions{})
		if err != nil {
			t.Fatalf("%s: marshal cyclonedx: %v", tc.name, err)
		}
		bom := new(cdx.BOM)
		if err := cdx.NewBOMDecoder(bytes.NewReader(out), cdx.BOMFileFormatJSON).Decode(bom); err != nil {
			t.Fatalf("%s: decode cyclonedx: %v", tc.name, err)
		}
		var got string
		if bom.Components != nil && len(*bom.Components) > 0 {
			got = (*bom.Components)[0].Copyright
		} else if bom.Metadata != nil && bom.Metadata.Component != nil {
			// A lone root may be published as the primary component instead.
			got = bom.Metadata.Component.Copyright
		}
		if got != tc.want {
			t.Fatalf("%s: cyclonedx copyright = %q, want %q", tc.name, truncate(got), truncate(tc.want))
		}
	}
}

// SPDX's two sentinels are not copyright text, and they stay that way.
func TestSPDXCopyrightSentinelsAreNotNotices(t *testing.T) {
	for _, value := range []string{"NOASSERTION", "NONE", "  NOASSERTION  ", ""} {
		if got := parseSPDXCopyright(value); got != "" {
			t.Fatalf("parseSPDXCopyright(%q) = %q, want empty", value, got)
		}
	}
	if got := parseSPDXCopyright("  Copyright Acme  "); got != "Copyright Acme" {
		t.Fatalf("parseSPDXCopyright trimmed to %q", got)
	}
}

func truncate(value string) string {
	if len(value) > 40 {
		return value[:40] + "..."
	}
	return value
}
