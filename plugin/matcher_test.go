package plugin

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk/internal/deepcopytest"
	"github.com/bomly-dev/bomly-sdk/model"
)

// requestFixture returns the graph, registry and target a matcher or
// analyzer request carries, each populated and wired together.
func requestFixture(t *testing.T) (*model.Graph, *model.PackageRegistry, *model.DependencyNode) {
	t.Helper()
	graph := model.New()
	var target *model.DependencyNode
	for _, raw := range []string{"pkg:npm/a@1.0.0", "pkg:npm/b@2.0.0?arch=x86"} {
		node, err := model.NewDependencyNodeFromPURL(raw)
		if err != nil {
			t.Fatalf("NewDependencyNodeFromPURL(%q): %v", raw, err)
		}
		node.Scopes = []model.Scope{model.ScopeRuntime}
		node.Metadata = map[string]any{"nested": map[string]any{"list": []any{"x"}}}
		if err := graph.AddNode(node); err != nil {
			t.Fatalf("AddNode: %v", err)
		}
		target = node
	}
	if err := graph.AddEdge("pkg:npm/a@1.0.0", target.NodeID()); err != nil {
		t.Fatalf("AddEdge: %v", err)
	}
	registry := model.NewPackageRegistry()
	for _, purl := range []string{"pkg:npm/a@1.0.0", target.NodeID()} {
		var pkg model.Package
		deepcopytest.Fill(&pkg)
		pkg.PURL, pkg.ID = purl, purl
		registry.Add(&pkg)
	}
	return graph, registry, target.Clone()
}

// assertRequestSharesNothing fails on every alias but Stderr, which a
// request clone keeps on purpose: it is the host's writer.
func assertRequestSharesNothing(t *testing.T, source, clone any) {
	t.Helper()
	for _, alias := range deepcopytest.Aliases(source, clone) {
		if !strings.HasPrefix(alias, "$.Stderr") {
			t.Errorf("request clone aliases its source at %s", alias)
		}
	}
}

func TestMatchRequestCloneSharesNothing(t *testing.T) {
	graph, registry, target := requestFixture(t)
	var source MatchRequest
	deepcopytest.Fill(&source)
	source.Graph, source.Registry, source.Target = graph, registry, target
	source.Stderr = &bytes.Buffer{}

	clone := source.Clone()
	if !reflect.DeepEqual(source, clone) {
		t.Fatal("clone differs from its source")
	}
	assertRequestSharesNothing(t, source, clone)
	if clone.Stderr != source.Stderr {
		t.Error("the clone does not keep the host's Stderr writer")
	}

	// What an embedded matcher that mutates its request in place does.
	pkg, _ := clone.Registry.Get("pkg:npm/a@1.0.0")
	pkg.Matched = false
	pkg.Vulnerabilities = nil
	clone.Target.Metadata["changed"] = true
	clone.Graph.RemoveNode("pkg:npm/a@1.0.0")
	clone.MatcherFilter.Include[0] = "changed"
	if stored, _ := source.Registry.Get("pkg:npm/a@1.0.0"); !stored.Matched || len(stored.Vulnerabilities) == 0 {
		t.Error("mutating the cloned registry changed the source")
	}
	if _, ok := source.Graph.Node("pkg:npm/a@1.0.0"); !ok {
		t.Error("mutating the cloned graph changed the source")
	}
	if _, ok := source.Target.Metadata["changed"]; ok || source.MatcherFilter.Include[0] == "changed" {
		t.Error("mutating the cloned target or filter changed the source")
	}

	var empty MatchRequest
	if got := empty.Clone(); got.Graph != nil || got.Registry != nil || got.Target != nil {
		t.Error("a request without graph, registry or target clones to one with them")
	}
}
