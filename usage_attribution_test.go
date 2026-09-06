package sdk

import (
	"path/filepath"
	"testing"
)

// sitedNode builds one dependency node with the sites given, so a test can
// state exactly what the producer recorded and nothing else.
func sitedNode(t *testing.T, name string, locations ...PackageLocation) *DependencyNode {
	t.Helper()
	node, err := NewDependencyNode(Coordinates{Name: name, Version: "1.0.0", Ecosystem: EcosystemNPM})
	if err != nil {
		t.Fatalf("NewDependencyNode(%s): %v", name, err)
	}
	node.Locations = locations
	return node
}

// graphOf wires nodes into a graph, which is what NewRootAttributor
// calibrates against.
func graphOf(t *testing.T, nodes ...*DependencyNode) *Graph {
	t.Helper()
	g := New()
	for _, node := range nodes {
		if err := g.AddNode(node); err != nil {
			t.Fatalf("AddNode(%s): %v", node.NodeID(), err)
		}
	}
	return g
}

// TestDeclaredRootAttributesTheSiteAndExcludesTheOthers is the rule at its
// simplest: a site that names this root establishes the occurrence, and --
// once the two vocabularies are known to overlap -- a site that names only
// another root says the node is not here at all.
func TestDeclaredRootAttributesTheSiteAndExcludesTheOthers(t *testing.T) {
	node := sitedNode(t, "left-pad", PackageLocation{ModuleRoot: "/ws/api"})
	attributor := NewRootAttributor([]string{"/ws/api", "/ws/web"}, graphOf(t, node))

	if got := attributor.Attribute(node, "/ws/api"); got != AttributedToSite {
		t.Errorf("Attribute(own root) = %v, want %v", got, AttributedToSite)
	}
	if got := attributor.Attribute(node, "/ws/web"); got != AttributedElsewhere {
		t.Errorf("Attribute(other root) = %v, want %v", got, AttributedElsewhere)
	}
}

// TestDeclaredRootsAreOnlyTrustedWhenTheyShareOurVocabulary guards the
// degradation path, which is the half most likely to be lost in a rewrite.
// Detectors record the root they resolved from and an analyzer derives roots
// from the filesystem; when the two spellings do not overlap, a non-match
// means they are speaking past each other, not that the package is absent --
// and dropping the node would lose the finding outright.
func TestDeclaredRootsAreOnlyTrustedWhenTheyShareOurVocabulary(t *testing.T) {
	node := sitedNode(t, "left-pad", PackageLocation{ModuleRoot: "apps/api", RealPath: "apps/api/package.json"})
	attributor := NewRootAttributor([]string{"/ws/api", "/ws/web"}, graphOf(t, node))

	if got := attributor.Attribute(node, "/ws/api"); got != AttributedToRootOnly {
		t.Errorf("Attribute under a foreign vocabulary = %v, want %v: the evidence must survive with the root as its floor", got, AttributedToRootOnly)
	}
}

// TestOneOverlappingSiteCalibratesTheWholePass pins that calibration is a
// property of the run, not of the node in hand: the node that shares the
// vocabulary licenses reading the other node's mismatch as absence.
func TestOneOverlappingSiteCalibratesTheWholePass(t *testing.T) {
	overlapping := sitedNode(t, "left-pad", PackageLocation{ModuleRoot: "/ws/web"})
	foreign := sitedNode(t, "right-pad", PackageLocation{ModuleRoot: "/elsewhere/lib"})
	attributor := NewRootAttributor([]string{"/ws/api", "/ws/web"}, graphOf(t, overlapping, foreign))

	if got := attributor.Attribute(foreign, "/ws/api"); got != AttributedElsewhere {
		t.Errorf("Attribute(node declaring only a foreign root) = %v, want %v once the run's roots are known to be the same vocabulary", got, AttributedElsewhere)
	}
}

// TestSitePathAttributesWithoutADeclaredRoot covers the path half of the
// rule. A vendored or nested copy lives inside the module that installed it,
// so its path alone says which root it belongs to.
func TestSitePathAttributesWithoutADeclaredRoot(t *testing.T) {
	apiRoot := filepath.Join("/ws", "api")
	webRoot := filepath.Join("/ws", "web")
	node := sitedNode(t, "left-pad", PackageLocation{
		RealPath: filepath.Join(apiRoot, "node_modules", "left-pad", "index.js"),
	})
	attributor := NewRootAttributor([]string{apiRoot, webRoot}, graphOf(t, node))

	if got := attributor.Attribute(node, apiRoot); got != AttributedToSite {
		t.Errorf("Attribute(root containing the site) = %v, want %v", got, AttributedToSite)
	}
	if got := attributor.Attribute(node, webRoot); got != AttributedElsewhere {
		t.Errorf("Attribute(sibling root) = %v, want %v: the copy is installed in a tree this run knows about, and it is not this one", got, AttributedElsewhere)
	}
}

// TestSiteOutsideEveryAnalyzedRootIsNotAbsence separates "installed
// somewhere else we analyze" from "installed somewhere we know nothing
// about". A module cache or a global store says nothing either way, and
// reading it as absence would drop every Go and Python finding.
func TestSiteOutsideEveryAnalyzedRootIsNotAbsence(t *testing.T) {
	node := sitedNode(t, "left-pad", PackageLocation{
		RealPath: filepath.Join("/home", "user", "go", "pkg", "mod", "left-pad@v1.0.0", "lib.go"),
	})
	attributor := NewRootAttributor([]string{"/ws/api", "/ws/web"}, graphOf(t, node))

	if got := attributor.Attribute(node, "/ws/api"); got != AttributedToRootOnly {
		t.Errorf("Attribute(site in a shared store) = %v, want %v", got, AttributedToRootOnly)
	}
}

// TestSiblingRootPrefixIsNotContainment pins that containment is a question
// about path elements, not about string prefixes: "/ws/apifoo" is not inside
// "/ws/api", and treating it as inside would attribute one module's install
// tree to its neighbour.
func TestSiblingRootPrefixIsNotContainment(t *testing.T) {
	node := sitedNode(t, "left-pad", PackageLocation{
		RealPath: filepath.Join("/ws", "apifoo", "node_modules", "left-pad", "index.js"),
	})
	attributor := NewRootAttributor([]string{"/ws/api"}, graphOf(t, node))

	if got := attributor.Attribute(node, "/ws/api"); got != AttributedToRootOnly {
		t.Errorf("Attribute(sibling whose name shares a prefix) = %v, want %v", got, AttributedToRootOnly)
	}
}

// TestDirectoryNamedLikeAnEscapeIsStillInsideTheRoot pins the containment
// test against the near miss the copies carried: a leading ".." must be a
// whole path element. Kubernetes secret mounts really do name a directory
// "..data", and reading that as an escape puts a site outside the root that
// contains it.
func TestDirectoryNamedLikeAnEscapeIsStillInsideTheRoot(t *testing.T) {
	root := filepath.Join("/ws", "api")
	node := sitedNode(t, "left-pad", PackageLocation{
		RealPath: filepath.Join(root, "..data", "node_modules", "left-pad", "index.js"),
	})
	attributor := NewRootAttributor([]string{root}, graphOf(t, node))

	if got := attributor.Attribute(node, root); got != AttributedToSite {
		t.Errorf("Attribute(site under a %q directory) = %v, want %v", "..data", got, AttributedToSite)
	}
}

// TestUncomparablePathsDoNotAttribute covers the mismatch filepath.Rel
// reports: a relative site path against an absolute root is neither inside
// nor outside it, and must read as neither.
func TestUncomparablePathsDoNotAttribute(t *testing.T) {
	node := sitedNode(t, "left-pad", PackageLocation{RealPath: filepath.Join("apps", "api", "package.json")})
	attributor := NewRootAttributor([]string{"/ws/api"}, graphOf(t, node))

	if got := attributor.Attribute(node, "/ws/api"); got != AttributedToRootOnly {
		t.Errorf("Attribute(relative site, absolute root) = %v, want %v", got, AttributedToRootOnly)
	}
}

// TestAttributeEdgeCasesKeepEvidence pins the answers that must never drop a
// finding: an unattributed node, an empty root (the whole-scan claim), and a
// zero-value attributor.
func TestAttributeEdgeCasesKeepEvidence(t *testing.T) {
	sited := sitedNode(t, "left-pad", PackageLocation{ModuleRoot: "/ws/api", RealPath: "/ws/api/package.json"})
	bare := sitedNode(t, "right-pad")
	attributor := NewRootAttributor([]string{"/ws/api"}, graphOf(t, sited, bare))

	if got := attributor.Attribute(bare, "/ws/api"); got != AttributedToRootOnly {
		t.Errorf("Attribute(node with no sites) = %v, want %v", got, AttributedToRootOnly)
	}
	if got := attributor.Attribute(sited, ""); got != AttributedToRootOnly {
		t.Errorf("Attribute(empty root) = %v, want %v: a whole-scan claim covers every site", got, AttributedToRootOnly)
	}
	if got := attributor.Attribute(sited, "   "); got != AttributedToRootOnly {
		t.Errorf("Attribute(blank root) = %v, want %v", got, AttributedToRootOnly)
	}

	var zero RootAttributor
	if got := zero.Attribute(sited, "/ws/api"); got != AttributedToSite {
		t.Errorf("zero attributor on the node's own root = %v, want %v", got, AttributedToSite)
	}
	if got := zero.Attribute(sited, "/ws/web"); got != AttributedToRootOnly {
		t.Errorf("zero attributor on another root = %v, want %v: knowing no roots means trusting no mismatch", got, AttributedToRootOnly)
	}
}

// TestAttributeNilNodeIsElsewhere keeps a typed nil from acquiring evidence.
func TestAttributeNilNodeIsElsewhere(t *testing.T) {
	attributor := NewRootAttributor([]string{"/ws/api"}, nil)
	if got := attributor.Attribute(nil, "/ws/api"); got != AttributedElsewhere {
		t.Errorf("Attribute(nil node) = %v, want %v", got, AttributedElsewhere)
	}
	if got := attributor.Attribute(nil, ""); got != AttributedElsewhere {
		t.Errorf("Attribute(nil node, empty root) = %v, want %v", got, AttributedElsewhere)
	}
}

// TestNewRootAttributorToleratesAnEmptyRun covers the inputs a caller can
// hand it before it knows anything: no roots, no graph, blank spellings.
func TestNewRootAttributorToleratesAnEmptyRun(t *testing.T) {
	node := sitedNode(t, "left-pad", PackageLocation{ModuleRoot: "/ws/api"})

	for _, tc := range []struct {
		name       string
		attributor RootAttributor
	}{
		{"nil graph", NewRootAttributor([]string{"/ws/web"}, nil)},
		{"no roots", NewRootAttributor(nil, graphOf(t, node))},
		{"blank roots", NewRootAttributor([]string{"", "  "}, graphOf(t, node))},
	} {
		if got := tc.attributor.Attribute(node, "/ws/web"); got != AttributedToRootOnly {
			t.Errorf("%s: Attribute = %v, want %v: an uncalibrated run keeps the evidence", tc.name, got, AttributedToRootOnly)
		}
	}
}

// TestRootAttributionString keeps diagnostics readable; a failure message
// that prints "2" says nothing about what was claimed.
func TestRootAttributionString(t *testing.T) {
	for _, tc := range []struct {
		attribution RootAttribution
		want        string
	}{
		{AttributedElsewhere, "attributed-elsewhere"},
		{AttributedToRootOnly, "attributed-to-root-only"},
		{AttributedToSite, "attributed-to-site"},
		{RootAttribution(7), "root-attribution(7)"},
	} {
		if got := tc.attribution.String(); got != tc.want {
			t.Errorf("RootAttribution(%d).String() = %q, want %q", int(tc.attribution), got, tc.want)
		}
	}
}
