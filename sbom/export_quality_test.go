package sbom

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bomly-dev/bomly-sdk/internal/testnodes"
	"github.com/spdx/tools-golang/spdx/v2/common"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"

	"github.com/bomly-dev/bomly-sdk/model"
)

// mustMultiRootGraph builds a graph with two disconnected roots, mirroring a
// scan that discovered manifests from more than one ecosystem.
func mustMultiRootGraph(t *testing.T) *model.Graph {
	t.Helper()

	g := model.New()
	workflow := testnodes.Ref("ci.yml", "local")
	action := testnodes.Ref("actions/checkout", "4.0.0")
	app := testnodes.Ref("app", "1.0.0")
	react := testnodes.Ref("react", "18.2.0")

	for _, n := range []*model.DependencyNode{workflow, action, app, react} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add package %s: %v", n.NodeID(), err)
		}
	}
	if err := g.AddEdge(workflow.NodeID(), action.NodeID()); err != nil {
		t.Fatalf("add edge workflow->action: %v", err)
	}
	if err := g.AddEdge(app.NodeID(), react.NodeID()); err != nil {
		t.Fatalf("add edge app->react: %v", err)
	}
	return g
}

func TestFromDepGraph_SynthesizesProjectRootForMultiRootGraphs(t *testing.T) {
	doc, err := FromDepGraph(mustMultiRootGraph(t), BuildOptions{
		DocumentName: "demo-project",
		ProjectRoot:  &ProjectRoot{Name: "demo-project", Version: "v1.2.3"},
	})
	if err != nil {
		t.Fatalf("from depgraph: %v", err)
	}

	if len(doc.Roots) != 1 {
		t.Fatalf("expected a single synthesized root, got %v", doc.Roots)
	}
	rootID := doc.Roots[0]
	if !strings.HasPrefix(rootID, projectRootIDPrefix) {
		t.Fatalf("expected pseudo root prefix on %q", rootID)
	}

	var root *Component
	for i := range doc.Components {
		if doc.Components[i].ID == rootID {
			root = &doc.Components[i]
		}
	}
	if root == nil {
		t.Fatalf("synthesized root %q missing from components", rootID)
	}
	if root.Name != "demo-project" || root.Version != "v1.2.3" || root.Type != "application" {
		t.Fatalf("unexpected root identity: %+v", root)
	}
	if root.PURL != "pkg:generic/demo-project@v1.2.3" {
		t.Fatalf("unexpected root purl: %q", root.PURL)
	}
	if !IsProjectRootComponent(*root) {
		t.Fatalf("expected IsProjectRootComponent to detect %q", rootID)
	}

	var rootDeps []string
	for _, dep := range doc.Dependencies {
		if dep.Ref == rootID {
			rootDeps = dep.DependsOn
		}
	}
	if len(rootDeps) != 2 {
		t.Fatalf("expected the pseudo root to depend on both graph roots, got %v", rootDeps)
	}
}

func TestFromDepGraph_KeepsSingleRootWithoutSynthesis(t *testing.T) {
	doc, err := FromDepGraph(mustGraph(t), BuildOptions{
		DocumentName: "demo-project",
		ProjectRoot:  &ProjectRoot{Name: "demo-project"},
	})
	if err != nil {
		t.Fatalf("from depgraph: %v", err)
	}
	if len(doc.Roots) != 1 || strings.HasPrefix(doc.Roots[0], projectRootIDPrefix) {
		t.Fatalf("expected the natural single root, got %v", doc.Roots)
	}
	for _, c := range doc.Components {
		if IsProjectRootComponent(c) {
			t.Fatalf("unexpected synthesized root %q", c.ID)
		}
	}
}

var uuidURNPattern = regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestFromDepGraph_GeneratesSerialNumberAndAlignedNamespace(t *testing.T) {
	doc, err := FromDepGraph(mustGraph(t), BuildOptions{})
	if err != nil {
		t.Fatalf("from depgraph: %v", err)
	}
	if !uuidURNPattern.MatchString(doc.SerialNumber) {
		t.Fatalf("expected an urn:uuid serial number, got %q", doc.SerialNumber)
	}
	nonce := strings.TrimPrefix(doc.SerialNumber, "urn:uuid:")
	if doc.Namespace != "https://bomly.dev/spdx/"+nonce {
		t.Fatalf("expected namespace to reuse the serial nonce, got %q vs serial %q", doc.Namespace, doc.SerialNumber)
	}

	explicit, err := FromDepGraph(mustGraph(t), BuildOptions{SerialNumber: "urn:uuid:00000000-0000-4000-8000-000000000000"})
	if err != nil {
		t.Fatalf("from depgraph: %v", err)
	}
	if explicit.SerialNumber != "urn:uuid:00000000-0000-4000-8000-000000000000" {
		t.Fatalf("explicit serial number was not preserved: %q", explicit.SerialNumber)
	}
}

func TestFromDepGraph_ProjectsDetectionTimeDigests(t *testing.T) {
	g := model.New()
	dep := testnodes.DepFrom(model.DependencyNode{
		Coordinates: model.Coordinates{Name: "left-pad", Version: "1.3.0", Ecosystem: model.EcosystemNPM},
		// npm SRI integrity values are base64; expect hex in the SBOM model.
		Digests: []model.Digest{
			{Algorithm: "sha512", Value: "pkJf8Ni4YWlKDgODlNGxi/z1Wd0/hkJH8N4Rq+Cd1lTv7ZZKPXm8mTzcp2xEVSlHoQlUwjzUKh2nGSHTMEUUpg=="},
			{Algorithm: "nuget-content-hash", Value: "abc123"},
		},
	})
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("add node: %v", err)
	}

	doc, err := FromDepGraph(g, BuildOptions{})
	if err != nil {
		t.Fatalf("from depgraph: %v", err)
	}
	if len(doc.Components) != 1 {
		t.Fatalf("expected one component, got %d", len(doc.Components))
	}
	digests := doc.Components[0].Digests
	if len(digests) != 2 {
		t.Fatalf("expected both digests projected, got %+v", digests)
	}
	if digests[0].Algorithm != "sha512" || len(digests[0].Value) != 128 {
		t.Fatalf("expected the sha512 digest re-encoded as 128 hex chars, got %+v", digests[0])
	}
	if strings.ToLower(digests[0].Value) != digests[0].Value {
		t.Fatalf("expected lowercase hex, got %q", digests[0].Value)
	}
	if digests[1].Algorithm != "nuget-content-hash" || digests[1].Value != "abc123" {
		t.Fatalf("expected unknown-algorithm digest kept verbatim, got %+v", digests[1])
	}
}

func TestMarshalDepGraphJSON_CycloneDXDocumentIdentityAndProvenance(t *testing.T) {
	out, err := MarshalDepGraphJSON(mustMultiRootGraph(t), TargetCycloneDX17JSON, BuildOptions{
		DocumentName: "demo-project",
		ProjectRoot:  &ProjectRoot{Name: "demo-project", Version: "v1.2.3"},
		ToolVersion:  "9.9.9",
		ToolNames:    []string{"bomly-detector:demo"},
		Provenance: Provenance{
			Manufacturer:               "Example Org",
			SecurityContact:            "security@example.com",
			VulnerabilityDisclosureURL: "https://example.com/security",
			SupportEnd:                 "2030-12-31",
		},
	}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal cyclonedx: %v", err)
	}

	var bom cdx.BOM
	if err := json.Unmarshal(out, &bom); err != nil {
		t.Fatalf("unmarshal cyclonedx: %v", err)
	}

	if !uuidURNPattern.MatchString(bom.SerialNumber) {
		t.Fatalf("expected generated serial number, got %q", bom.SerialNumber)
	}
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		t.Fatalf("expected metadata.component")
	}
	root := bom.Metadata.Component
	if root.Name != "demo-project" || root.Version != "v1.2.3" || root.PackageURL != "pkg:generic/demo-project@v1.2.3" {
		t.Fatalf("unexpected primary component: %+v", root)
	}
	if root.ExternalReferences == nil || len(*root.ExternalReferences) != 2 {
		t.Fatalf("expected security external references, got %+v", root.ExternalReferences)
	}
	refs := *root.ExternalReferences
	if refs[0].Type != cdx.ERTypeSecurityContact || refs[0].URL != "mailto:security@example.com" {
		t.Fatalf("unexpected security contact reference: %+v", refs[0])
	}
	if refs[1].Type != cdx.ERTypeAdvisories || refs[1].URL != "https://example.com/security" {
		t.Fatalf("unexpected disclosure reference: %+v", refs[1])
	}
	if bom.Metadata.Manufacturer == nil || bom.Metadata.Manufacturer.Name != "Example Org" {
		t.Fatalf("expected metadata.manufacturer, got %+v", bom.Metadata.Manufacturer)
	}
	if bom.Metadata.Properties == nil || len(*bom.Metadata.Properties) != 1 || (*bom.Metadata.Properties)[0].Name != "bomly:support_end_date" || (*bom.Metadata.Properties)[0].Value != "2030-12-31" {
		t.Fatalf("expected support end property, got %+v", bom.Metadata.Properties)
	}

	if bom.Metadata.Tools == nil || bom.Metadata.Tools.Components == nil {
		t.Fatalf("expected tools components")
	}
	toolVersions := map[string]string{}
	for _, tool := range *bom.Metadata.Tools.Components {
		toolVersions[tool.Name] = tool.Version
	}
	if toolVersions["bomly-cli"] != "9.9.9" {
		t.Fatalf("expected primary tool version, got %+v", toolVersions)
	}
	if toolVersions["bomly-detector:demo"] != "" {
		t.Fatalf("expected detector tools to stay unversioned, got %+v", toolVersions)
	}

	// The pseudo root must not be double-counted in the component inventory,
	// but its dependency entry must link the document root to the graph roots.
	if bom.Components == nil {
		t.Fatalf("expected components")
	}
	for _, comp := range *bom.Components {
		if comp.BOMRef == root.BOMRef {
			t.Fatalf("pseudo root %q duplicated in components", root.BOMRef)
		}
	}
	if bom.Dependencies == nil {
		t.Fatalf("expected dependencies")
	}
	foundRootEntry := false
	for _, dep := range *bom.Dependencies {
		if dep.Ref == root.BOMRef {
			foundRootEntry = true
			if dep.Dependencies == nil || len(*dep.Dependencies) != 2 {
				t.Fatalf("expected pseudo root dependency entry to list both graph roots, got %+v", dep.Dependencies)
			}
		}
	}
	if !foundRootEntry {
		t.Fatalf("missing dependency entry for pseudo root %q", root.BOMRef)
	}
}

func TestUnmarshalJSON_CycloneDXPseudoRootRoundTrip(t *testing.T) {
	out, err := MarshalDepGraphJSON(mustMultiRootGraph(t), TargetCycloneDX17JSON, BuildOptions{
		DocumentName: "demo-project",
		ProjectRoot:  &ProjectRoot{Name: "demo-project"},
	}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal cyclonedx: %v", err)
	}

	doc, err := UnmarshalJSON(out, TargetCycloneDX17JSON)
	if err != nil {
		t.Fatalf("unmarshal cyclonedx: %v", err)
	}
	if len(doc.Components) != 4 {
		t.Fatalf("expected the four real components, got %d", len(doc.Components))
	}
	if len(doc.Roots) != 2 {
		t.Fatalf("expected both real graph roots after decode, got %v", doc.Roots)
	}

	g, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	if g.Size() != 4 {
		t.Fatalf("expected 4 graph nodes, got %d", g.Size())
	}
}

func TestToGraph_SkipsSynthesizedProjectRootWithPURL(t *testing.T) {
	doc := &Document{
		Components: []Component{
			{ID: projectRootIDPrefix + "demo", Name: "demo", Type: "application", PURL: "pkg:generic/demo"},
			{ID: "pkg:npm/react@18.2.0", Name: "react", Version: "18.2.0", PURL: "pkg:npm/react@18.2.0"},
		},
		Dependencies: []Dependency{
			{Ref: projectRootIDPrefix + "demo", DependsOn: []string{"pkg:npm/react@18.2.0"}},
			{Ref: "pkg:npm/react@18.2.0"},
		},
	}
	g, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	if g.Size() != 1 {
		t.Fatalf("expected pseudo root to be skipped, got %d nodes", g.Size())
	}
}

func TestMarshalDepGraphJSON_SPDX23ProvenanceAndToolVersion(t *testing.T) {
	out, err := MarshalDepGraphJSON(mustMultiRootGraph(t), TargetSPDX23JSON, BuildOptions{
		DocumentName: "demo-project",
		ProjectRoot:  &ProjectRoot{Name: "demo-project", Version: "v1.2.3"},
		ToolVersion:  "9.9.9",
		Provenance: Provenance{
			Manufacturer:               "Example Org",
			SecurityContact:            "security@example.com",
			VulnerabilityDisclosureURL: "https://example.com/security",
			SupportEnd:                 "2030-12-31",
		},
	}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}

	var d v23.Document
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}
	if d.DocumentName != "demo-project" {
		t.Fatalf("unexpected document name %q", d.DocumentName)
	}

	toolCreator, orgCreator := "", ""
	for _, c := range d.CreationInfo.Creators {
		switch c.CreatorType {
		case "Tool":
			if toolCreator == "" {
				toolCreator = c.Creator
			}
		case "Organization":
			orgCreator = c.Creator
		}
	}
	if toolCreator != "bomly-cli-9.9.9" {
		t.Fatalf("expected SPDX tool creator with version, got %q", toolCreator)
	}
	if orgCreator != "Example Org" {
		t.Fatalf("expected organization creator, got %q", orgCreator)
	}
	if !strings.Contains(d.CreationInfo.CreatorComment, "SecurityContact: security@example.com") ||
		!strings.Contains(d.CreationInfo.CreatorComment, "VulnerabilityDisclosure: https://example.com/security") ||
		!strings.Contains(d.CreationInfo.CreatorComment, "SupportEnd: 2030-12-31") {
		t.Fatalf("unexpected creator comment %q", d.CreationInfo.CreatorComment)
	}

	var root *v23.Package
	for _, p := range d.Packages {
		if strings.HasPrefix(string(p.PackageSPDXIdentifier), projectRootIDPrefix) {
			root = p
		}
	}
	if root == nil {
		t.Fatalf("expected synthesized root package in SPDX document")
	}
	if root.PrimaryPackagePurpose != "APPLICATION" {
		t.Fatalf("expected APPLICATION purpose on root, got %q", root.PrimaryPackagePurpose)
	}
	if root.PackageSupplier == nil || root.PackageSupplier.Supplier != "Example Org" {
		t.Fatalf("expected supplier on root, got %+v", root.PackageSupplier)
	}

	describesRoot := false
	for _, rel := range d.Relationships {
		if rel != nil && rel.Relationship == "DESCRIBES" && rel.RefB.ElementRefID == root.PackageSPDXIdentifier {
			describesRoot = true
		}
	}
	if !describesRoot {
		t.Fatalf("expected the document to describe the synthesized root")
	}
}

func TestFromDepGraph_StampsFirstPartyVersionFromProjectRoot(t *testing.T) {
	g := model.New()
	main := testnodes.ModuleFrom("go.mod", model.Coordinates{
		Name: "example.com/app", Ecosystem: model.EcosystemGo,
	})
	dep := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{
		Name: "example.com/lib", Version: "v1.0.0", Ecosystem: model.EcosystemGo,
	}})
	for _, n := range []model.GraphNode{main, dep} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node: %v", err)
		}
	}
	if err := g.AddEdge(main.NodeID(), dep.NodeID()); err != nil {
		t.Fatalf("add edge: %v", err)
	}

	doc, err := FromDepGraph(g, BuildOptions{ProjectRoot: &ProjectRoot{Name: "app", Version: "v2.3.4"}})
	if err != nil {
		t.Fatalf("from depgraph: %v", err)
	}
	for _, c := range doc.Components {
		if c.Name == "example.com/app" && c.Version != "v2.3.4" {
			t.Fatalf("expected first-party component to carry the project version, got %q", c.Version)
		}
		if c.Name == "example.com/lib" && c.Version != "v1.0.0" {
			t.Fatalf("third-party version must not be overwritten, got %q", c.Version)
		}
	}
}

func TestNormalizeSPDXLicenseExpression(t *testing.T) {
	cases := map[string]string{
		"GPL-2.0":  "GPL-2.0-only",
		"GPL-3.0+": "GPL-3.0-or-later",
		// spdxkit's canonical rendering drops the redundant outer parentheses
		// of a valid expression.
		"(MIT OR GPL-2.0)":    "MIT OR GPL-2.0-only",
		"MIT":                 "MIT",
		"Custom License Text": "Custom License Text",
		// Not a valid expression -- "addon" names no exception -- so it is
		// free text and nothing inside it is rewritten. The old token
		// rewrite produced "LGPL-2.1-only WITH addon", a claim the source
		// never made.
		"LGPL-2.1 WITH addon": "LGPL-2.1 WITH addon",
		"use GPL-2.0 here":    "use GPL-2.0 here",
		"":                    "",
	}
	for in, want := range cases {
		if got := normalizeSPDXLicenseExpression(in); got != want {
			t.Errorf("normalizeSPDXLicenseExpression(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMarshalDepGraphJSON_CycloneDXLifecycleCompositionAndAuthors(t *testing.T) {
	out, err := MarshalDepGraphJSON(mustMultiRootGraph(t), TargetCycloneDX17JSON, BuildOptions{
		ProjectRoot: &ProjectRoot{Name: "demo"},
		Lifecycle:   "pre-build",
		Aggregate:   "complete",
		Provenance: Provenance{
			Manufacturer:    "Example Org",
			SecurityContact: "security@example.com",
		},
	}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal cyclonedx: %v", err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(out, &bom); err != nil {
		t.Fatalf("unmarshal cyclonedx: %v", err)
	}
	if bom.Metadata.Lifecycles == nil || len(*bom.Metadata.Lifecycles) != 1 || (*bom.Metadata.Lifecycles)[0].Phase != cdx.LifecyclePhasePreBuild {
		t.Fatalf("expected pre-build lifecycle, got %+v", bom.Metadata.Lifecycles)
	}
	if bom.Compositions == nil || len(*bom.Compositions) != 1 || (*bom.Compositions)[0].Aggregate != cdx.CompositionAggregateComplete {
		t.Fatalf("expected complete composition, got %+v", bom.Compositions)
	}
	if bom.Metadata.Authors == nil || len(*bom.Metadata.Authors) != 1 {
		t.Fatalf("expected one author, got %+v", bom.Metadata.Authors)
	}
	author := (*bom.Metadata.Authors)[0]
	if author.Name != "Example Org" || author.Email != "security@example.com" {
		t.Fatalf("unexpected author: %+v", author)
	}
}

func TestMarshalDepGraphJSON_CycloneDXOmitsInvalidLifecycleAndAggregate(t *testing.T) {
	out, err := MarshalDepGraphJSON(mustGraph(t), TargetCycloneDX17JSON, BuildOptions{
		Lifecycle: "sometime",
		Aggregate: "mostly-done",
	}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal cyclonedx: %v", err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(out, &bom); err != nil {
		t.Fatalf("unmarshal cyclonedx: %v", err)
	}
	if bom.Metadata.Lifecycles != nil {
		t.Fatalf("invalid lifecycle should be omitted, got %+v", bom.Metadata.Lifecycles)
	}
	if bom.Compositions != nil {
		t.Fatalf("invalid aggregate should be omitted, got %+v", bom.Compositions)
	}
}

func TestMarshalDepGraphJSON_SPDX23PackagePurposes(t *testing.T) {
	g := model.New()
	workflow := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{
		Name: "ci.yml", Version: "local", Ecosystem: model.EcosystemGitHub, Type: model.ParsePackageType("workflow"),
	}})
	lib := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{
		Name: "react", Version: "18.2.0", Ecosystem: model.EcosystemNPM,
	}})
	for _, n := range []*model.DependencyNode{workflow, lib} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node: %v", err)
		}
	}

	out, err := MarshalDepGraphJSON(g, TargetSPDX23JSON, BuildOptions{ProjectRoot: &ProjectRoot{Name: "demo"}}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}
	var d v23.Document
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}
	purposes := map[string]string{}
	for _, p := range d.Packages {
		purposes[p.PackageName] = p.PrimaryPackagePurpose
	}
	if purposes["react"] != "LIBRARY" {
		t.Fatalf("expected LIBRARY purpose for react, got %q", purposes["react"])
	}
	if purposes["ci.yml"] != "OTHER" {
		t.Fatalf("expected OTHER purpose for workflow, got %q", purposes["ci.yml"])
	}
	if purposes["demo"] != "APPLICATION" {
		t.Fatalf("expected APPLICATION purpose for project root, got %q", purposes["demo"])
	}
}

func TestMarshalDepGraphJSON_SPDX23SupplierOnNaturalPrimaryPackage(t *testing.T) {
	// A single-root graph keeps its natural root as the primary component, so
	// no pseudo root is synthesized. Provenance must still land on it, the
	// way CycloneDX attaches it to metadata.component in both forms.
	out, err := MarshalDepGraphJSON(mustGraph(t), TargetSPDX23JSON, BuildOptions{
		ProjectRoot: &ProjectRoot{Name: "demo-project"},
		Provenance:  Provenance{Manufacturer: "Example Org"},
	}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}

	var d v23.Document
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}

	var describes common.ElementID
	for _, rel := range d.Relationships {
		if rel != nil && rel.Relationship == "DESCRIBES" {
			describes = rel.RefB.ElementRefID
		}
	}
	if describes == "" {
		t.Fatal("expected a DESCRIBES relationship")
	}

	suppliers := 0
	for _, p := range d.Packages {
		if p.PackageSPDXIdentifier != describes {
			if p.PackageSupplier != nil {
				t.Fatalf("supplier leaked onto non-root package %q", p.PackageName)
			}
			continue
		}
		if p.PackageSupplier == nil || p.PackageSupplier.Supplier != "Example Org" {
			t.Fatalf("expected supplier on the natural primary package, got %+v", p.PackageSupplier)
		}
		suppliers++
	}
	if suppliers != 1 {
		t.Fatalf("expected exactly one supplied package, got %d", suppliers)
	}
}

// A pinned identity slot fills the other from the same UUID: a build is one
// document, however the caller named it (issue #109). A namespace in a form
// that carries no UUID leaves the serial to be minted.
func TestFromDepGraph_PinnedIdentitySlotDerivesTheOther(t *testing.T) {
	const uuid = "0f3c9a2e-5d4b-4c6a-8e1f-7a2b3c4d5e6f"

	fromSerial, err := FromDepGraph(mustGraph(t), BuildOptions{SerialNumber: "urn:uuid:" + uuid})
	if err != nil {
		t.Fatalf("from depgraph: %v", err)
	}
	if fromSerial.Namespace != "https://bomly.dev/spdx/"+uuid {
		t.Errorf("namespace = %q, want the pinned serial's UUID", fromSerial.Namespace)
	}

	fromNamespace, err := FromDepGraph(mustGraph(t), BuildOptions{DocumentNS: "https://bomly.dev/spdx/" + uuid})
	if err != nil {
		t.Fatalf("from depgraph: %v", err)
	}
	if fromNamespace.SerialNumber != "urn:uuid:"+uuid {
		t.Errorf("serial = %q, want the pinned namespace's UUID", fromNamespace.SerialNumber)
	}

	foreign, err := FromDepGraph(mustGraph(t), BuildOptions{DocumentNS: "https://acme.example/spdx/release-7"})
	if err != nil {
		t.Fatalf("from depgraph: %v", err)
	}
	if foreign.Namespace != "https://acme.example/spdx/release-7" {
		t.Errorf("namespace = %q, want the pinned one kept", foreign.Namespace)
	}
	if !uuidURNPattern.MatchString(foreign.SerialNumber) {
		t.Errorf("serial = %q, want a freshly minted urn:uuid", foreign.SerialNumber)
	}

	malformed, err := FromDepGraph(mustGraph(t), BuildOptions{DocumentNS: "https://bomly.dev/spdx/not-a-uuid"})
	if err != nil {
		t.Fatalf("from depgraph: %v", err)
	}
	if !uuidURNPattern.MatchString(malformed.SerialNumber) {
		t.Errorf("serial = %q, want a freshly minted urn:uuid, not the namespace tail", malformed.SerialNumber)
	}
}

// The two encodings of one build describe one document: the same UUID in
// the SPDX namespace and the CycloneDX serial, the same lifecycle phase and
// document version, the same tools, the same timestamp. Measured on the CLI's
// two exports of one scan, these were the whole of a 56% difference between
// documents with identical inventories (issue #109).
func TestOneBuildEncodesToTheSameDocumentInBothFormats(t *testing.T) {
	doc, err := FromDepGraph(mustMultiRootGraph(t), BuildOptions{
		DocumentName: "demo-project",
		ProjectRoot:  &ProjectRoot{Name: "demo-project", Version: "v1.2.3-1-gabcdef0"},
		ToolVersion:  "0.28.2",
		ToolNames:    []string{"npm-detector", "github-actions-detector"},
		Lifecycle:    "pre-build",
		Provenance:   Provenance{SecurityContact: "security@example.com"},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	spdxRaw, err := MarshalJSON(doc, TargetSPDX23JSON, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}
	cdxRaw, err := MarshalJSON(doc, TargetCycloneDX17JSON, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal cyclonedx: %v", err)
	}
	var spdxDoc v23.Document
	if err := json.Unmarshal(spdxRaw, &spdxDoc); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(cdxRaw, &bom); err != nil {
		t.Fatalf("unmarshal cyclonedx: %v", err)
	}

	// One identity, spelled in each format's form.
	uuid := strings.TrimPrefix(bom.SerialNumber, "urn:uuid:")
	if uuid == "" || uuid == bom.SerialNumber {
		t.Fatalf("cyclonedx serial = %q, want an urn:uuid", bom.SerialNumber)
	}
	if spdxDoc.DocumentNamespace != "https://bomly.dev/spdx/"+uuid {
		t.Errorf("spdx namespace = %q, want the cyclonedx serial's UUID %s", spdxDoc.DocumentNamespace, uuid)
	}

	// The lifecycle phase and document version CycloneDX holds in fields and
	// SPDX 2.3 holds nowhere, carried in the creator comment.
	comment := spdxDoc.CreationInfo.CreatorComment
	if (*bom.Metadata.Lifecycles)[0].Phase != cdx.LifecyclePhasePreBuild || bom.Version != 1 ||
		!strings.HasSuffix(comment, "\nbomly:lifecycle=pre-build;document_version=1") {
		t.Errorf("lifecycle and version: cyclonedx %+v / %d, spdx creator comment %q", bom.Metadata.Lifecycles, bom.Version, comment)
	}
	if !strings.Contains(comment, "SecurityContact: security@example.com") {
		t.Errorf("creator comment lost the provenance it carried before: %q", comment)
	}

	// The same tools, each in its format's "name-version" or name+version
	// shape: SPDX "Tool: bomly-cli-0.28.2" is the specification's own
	// convention and stays.
	var spdxTools []string
	for _, creator := range spdxDoc.CreationInfo.Creators {
		if creator.CreatorType == "Tool" {
			spdxTools = append(spdxTools, creator.Creator)
		}
	}
	var cdxTools []string
	for _, tool := range *bom.Metadata.Tools.Components {
		rendered := tool.Name
		if tool.Version != "" {
			rendered += "-" + tool.Version
		}
		cdxTools = append(cdxTools, rendered)
	}
	if want := []string{"bomly-cli-0.28.2", "github-actions-detector", "npm-detector"}; strings.Join(spdxTools, ",") != strings.Join(want, ",") || strings.Join(cdxTools, ",") != strings.Join(want, ",") {
		t.Errorf("tools: spdx %v, cyclonedx %v, want both %v", spdxTools, cdxTools, want)
	}

	if spdxDoc.CreationInfo.Created != bom.Metadata.Timestamp {
		t.Errorf("created: spdx %q, cyclonedx %q", spdxDoc.CreationInfo.Created, bom.Metadata.Timestamp)
	}

	// And read back: an SPDX round trip keeps the phase and version the way
	// a CycloneDX one does.
	reread, err := UnmarshalJSON(spdxRaw, TargetSPDX23JSON)
	if err != nil {
		t.Fatalf("ingest spdx: %v", err)
	}
	if reread.Lifecycle != "pre-build" || reread.SerialVersion != 1 {
		t.Errorf("reread spdx: Lifecycle = %q, SerialVersion = %d, want pre-build and 1", reread.Lifecycle, reread.SerialVersion)
	}
}

// Two one-shot marshals are two builds, and so two documents: the API shape
// the CLI used when the divergence was measured. The test pins what the doc
// comments promise, so a caller who reads only this knows to build once.
func TestTwoMarshalsOfOneGraphAreTwoDocuments(t *testing.T) {
	first, err := MarshalDepGraphJSON(mustGraph(t), TargetCycloneDX17JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	second, err := MarshalDepGraphJSON(mustGraph(t), TargetSPDX23JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(first, &bom); err != nil {
		t.Fatalf("unmarshal cyclonedx: %v", err)
	}
	var spdxDoc v23.Document
	if err := json.Unmarshal(second, &spdxDoc); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}
	if uuid := strings.TrimPrefix(bom.SerialNumber, "urn:uuid:"); strings.HasSuffix(spdxDoc.DocumentNamespace, uuid) {
		t.Fatalf("two builds shared a UUID: serial %q, namespace %q", bom.SerialNumber, spdxDoc.DocumentNamespace)
	}
}

// The SPDX carrier is held to the same gates as the CycloneDX fields: a phase
// outside the vocabulary is absent from both documents, and a version that is
// not a positive integer reads back as unset. A comment someone else wrote
// in another shape is simply not read.
func TestSPDXCreatorCommentCarrierIsGated(t *testing.T) {
	out, err := MarshalDepGraphJSON(mustGraph(t), TargetSPDX23JSON, BuildOptions{Lifecycle: "sometime"}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}
	var spdxDoc v23.Document
	if err := json.Unmarshal(out, &spdxDoc); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}
	if comment := spdxDoc.CreationInfo.CreatorComment; comment != "bomly:document_version=1" {
		t.Errorf("creator comment = %q, want only the document version", comment)
	}

	for comment, want := range map[string]struct {
		lifecycle string
		version   int
	}{
		"bomly:lifecycle=post-build;document_version=3":                          {"post-build", 3},
		"SecurityContact: a@b.example\nbomly:lifecycle=build;document_version=2": {"build", 2},
		"bomly:Lifecycle=Build":                          {"build", 0},
		"bomly:lifecycle=sometime;document_version=zero": {"", 0},
		"bomly:document_version=0":                       {"", 0},
		"bomly:document_version=-1":                      {"", 0},
		// A third party's prose is not Bomly's claim, whatever words it uses.
		"Lifecycle: build; DocumentVersion: 3":   {"", 0},
		"Produced in the build; lifecycle=build": {"", 0},
		"Produced by hand":                       {"", 0},
		"":                                       {"", 0},
	} {
		ci := &v23.CreationInfo{CreatorComment: comment}
		if got := parseSPDXCreatorLifecycle(ci); got != want.lifecycle {
			t.Errorf("lifecycle of %q = %q, want %q", comment, got, want.lifecycle)
		}
		if got := parseSPDXCreatorDocumentVersion(ci); got != want.version {
			t.Errorf("version of %q = %d, want %d", comment, got, want.version)
		}
	}
	if parseSPDXCreatorLifecycle(nil) != "" || parseSPDXCreatorDocumentVersion(nil) != 0 {
		t.Error("nil creation info should read as unset")
	}
}
