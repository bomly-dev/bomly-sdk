package sbom

import (
	"encoding/json"
	"testing"

	"github.com/bomly-dev/bomly-sdk/internal/testnodes"
	"github.com/bomly-dev/bomly-sdk/model"
)

// The synthesized root stands for a source tree, which has no content hash
// to publish. A caller can say so in its own words, and both formats carry
// the words in the field they define for a component's description, so a
// consumer finds the explanation where it looks first (bomly-cli issue #508).
func TestProjectRootDescriptionIsPublishedInBothFormats(t *testing.T) {
	const description = "Source tree of the scanned project, not a distributed artifact: no content hash applies."

	// Two unrelated roots, so the projection has to synthesize the primary
	// component rather than promote a graph root.
	g := model.New()
	for _, n := range []*model.DependencyNode{testnodes.Ref("left", "1.0.0"), testnodes.Ref("right", "2.0.0")} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %s: %v", n.NodeID(), err)
		}
	}
	opts := BuildOptions{
		DocumentName: "demo",
		ToolVersion:  "test",
		ProjectRoot:  &ProjectRoot{Name: "demo", Version: "v1.0.0", Description: description},
	}

	cdxRaw, err := MarshalDepGraphJSON(g, TargetCycloneDX17JSON, opts, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal CycloneDX: %v", err)
	}
	var cdx struct {
		Metadata struct {
			Component struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"component"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(cdxRaw, &cdx); err != nil {
		t.Fatalf("decode CycloneDX: %v", err)
	}
	if cdx.Metadata.Component.Name != "demo" || cdx.Metadata.Component.Description != description {
		t.Errorf("CycloneDX metadata.component = %+v, want name demo with the description", cdx.Metadata.Component)
	}

	spdxRaw, err := MarshalDepGraphJSON(g, TargetSPDX23JSON, opts, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal SPDX: %v", err)
	}
	if got := spdxPackageByName(t, spdxRaw, "demo")["description"]; got != description {
		t.Errorf("SPDX root package description = %v, want %q", got, description)
	}

	// Without a description the field stays absent: the caller said nothing,
	// and the document must not say it for them.
	opts.ProjectRoot = &ProjectRoot{Name: "demo", Version: "v1.0.0"}
	spdxRaw, err = MarshalDepGraphJSON(g, TargetSPDX23JSON, opts, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal SPDX without description: %v", err)
	}
	if got, present := spdxPackageByName(t, spdxRaw, "demo")["description"]; present && got != "" {
		t.Errorf("SPDX root package description = %v, want none", got)
	}
}
