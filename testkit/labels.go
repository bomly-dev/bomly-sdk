package testkit

import (
	"strings"
	"testing"

	sdk "github.com/bomly-dev/bomly-sdk"
)

// Looking a fixture node up by the label it was written as.
//
// A node's ID is a canonical package URL now (ADR-0041), so a test can no
// longer find a node by the "name@version" string its fixture was built
// from. Rewriting every lookup to a package URL spreads the identity rules
// across hundreds of literals and hides, rather than pins, what each case is
// about -- and gets them wrong in the same way twice: a scoped npm name
// splits into org and name, a Maven group is a namespace, a version that
// looks lowercase is not.
//
// So the label stays in the test and these resolve it. They are for fixtures,
// not for production lookups: a caller that knows the identity should use
// Graph.Node or Graph.DependencyNode directly.

// MustManifestNode constructs a manifest node and fails the test when the
// constructor rejects the path or kind.
func MustManifestNode(t testing.TB, path string, kind sdk.ManifestKind) *sdk.ManifestNode {
	t.Helper()
	node, err := sdk.NewManifestNode(path, kind)
	if err != nil {
		t.Fatalf("NewManifestNode(%q, %q): %v", path, kind, err)
	}
	return node
}

// MustDependencyFrom constructs a dependency node from a prototype, copying
// every field the prototype states, and fails the test when the coordinates
// cannot mint an identity. Test-fixture counterpart of
// sdk.NewDependencyNodeFrom.
func MustDependencyFrom(t testing.TB, proto sdk.DependencyNode) *sdk.DependencyNode {
	t.Helper()
	node, err := sdk.NewDependencyNodeFrom(proto)
	if err != nil {
		t.Fatalf("NewDependencyNodeFrom(%q): %v", proto.Name, err)
	}
	return node
}

// FindNode returns the node a "name@version" label names, and whether one
// matched.
//
// A label matches a node's ID outright, or its name and version in any of the
// spellings the node answers to: the bare name, the ecosystem-native name,
// and the display name. A label with no version matches on name alone, which
// is what a module or manifest label looks like.
func FindNode(g *sdk.Graph, label string) (sdk.GraphNode, bool) {
	if g == nil {
		return nil, false
	}
	if node, ok := g.Node(label); ok {
		return node, true
	}
	name, version := SplitNodeLabel(label)
	// Exact spellings first, then the loose ones, so a label that names one
	// node exactly is never answered with a near miss from elsewhere in the
	// graph.
	for _, loose := range []bool{false, true} {
		for _, node := range g.Nodes() {
			if nodeMatchesLabel(node, name, version, loose) {
				return node, true
			}
		}
	}
	return nil, false
}

// FindDependencyNode is FindNode narrowed to a dependency node.
func FindDependencyNode(g *sdk.Graph, label string) (*sdk.DependencyNode, bool) {
	node, ok := FindNode(g, label)
	if !ok {
		return nil, false
	}
	return sdk.AsDependencyNode(node)
}

// NodeID returns the ID of the node a label names, or the label unchanged
// when nothing matches -- so a lookup meant to fail still fails, with the
// label in the error where a reader expects it.
//
// Use it where a graph method takes an ID rather than returning a node:
// DirectDependencies, Dependents, CollectPathsTo, AddEdge.
func NodeID(g *sdk.Graph, label string) string {
	if node, ok := FindNode(g, label); ok {
		return node.NodeID()
	}
	return label
}

// NodeIs reports whether a node answers to a label: by ID, or by any of the
// spellings its coordinates carry. It is the comparison form of FindNode, for
// assertions that hold a node and want to know which one it is.
func NodeIs(node sdk.GraphNode, label string) bool {
	if sdk.IsNilNode(node) {
		return false
	}
	if node.NodeID() == label {
		return true
	}
	name, version := SplitNodeLabel(label)
	return nodeMatchesLabel(node, name, version, true)
}

// SplitNodeLabel splits "name@version" at the last "@", so a scoped npm name
// ("@scope/pkg@1.2.3") splits where it should.
func SplitNodeLabel(label string) (name, version string) {
	if at := strings.LastIndex(label, "@"); at > 0 {
		return label[:at], label[at+1:]
	}
	return label, ""
}

// labelSpellings lists the ways a label may name one node.
//
// The loose forms exist because these labels were the pre-ADR-0041 node IDs,
// and detectors minted those with their own separators and kind prefixes:
// composer wrote "vendor:shared" for the package "vendor/shared", GitHub
// Actions wrote "action:.github/actions/local-setup" for a local action whose
// name is its path.
func labelSpellings(name string, loose bool) []string {
	spellings := []string{name}
	if !loose {
		return spellings
	}
	spellings = append(spellings, strings.ReplaceAll(name, ":", "/"))
	if colon := strings.Index(name, ":"); colon > 0 {
		spellings = append(spellings, name[colon+1:])
	}
	return spellings
}

func nodeMatchesLabel(node sdk.GraphNode, name, version string, loose bool) bool {
	if manifest, ok := node.(*sdk.ManifestNode); ok && manifest != nil {
		return version == "" && manifest.Path == name
	}
	coords, ok := sdk.NodeCoordinates(node)
	if !ok {
		return false
	}
	if version != "" && coords.Version != version {
		// Coordinates are normalized at construction, and some ecosystems
		// canonicalize a version's case, so a label written as the manifest
		// spelled it need not match exactly. The loose pass accepts it.
		if !loose || !strings.EqualFold(coords.Version, version) {
			return false
		}
	}
	actual := []string{coords.Name, coords.EcosystemName(), coords.DisplayName()}
	for _, want := range labelSpellings(name, loose) {
		for _, got := range actual {
			if got == want {
				return true
			}
		}
	}
	return false
}
