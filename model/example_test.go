package model_test

import (
	"fmt"

	"github.com/bomly-dev/bomly-sdk/model"
)

func mustNode(purl string) *model.DependencyNode {
	node, err := model.NewDependencyNodeFromPURL(purl)
	if err != nil {
		panic(err)
	}
	return node
}

// A graph is built from nodes whose identity is their canonical package
// URL, joined by edges; every iteration is ordered by ID.
func ExampleGraph() {
	g := model.New()
	app := mustNode("pkg:npm/app@1.0.0")
	react := mustNode("pkg:npm/react@18.2.0")
	react.Scopes = []model.Scope{model.ScopeRuntime}
	jest := mustNode("pkg:npm/jest@29.0.0")
	jest.Scopes = []model.Scope{model.ScopeDevelopment}
	for _, node := range []*model.DependencyNode{app, react, jest} {
		if err := g.AddNode(node); err != nil {
			panic(err)
		}
	}
	_ = g.AddEdge(app.NodeID(), react.NodeID())
	_ = g.AddEdge(app.NodeID(), jest.NodeID())

	for _, dep := range g.DependencyNodes() {
		children, _ := g.DirectDependencies(dep.NodeID())
		fmt.Println(dep.NodeID(), len(children))
	}
	// Output:
	// pkg:npm/app@1.0.0 2
	// pkg:npm/jest@29.0.0 0
	// pkg:npm/react@18.2.0 0
}

// A scope filter selects on assertions: a node that asserted no scope is
// kept by a runtime view, and the report says how many were kept that way.
func ExampleFilterGraphByScopeWithReport() {
	g := model.New()
	runtime := mustNode("pkg:npm/react@18.2.0")
	runtime.Scopes = []model.Scope{model.ScopeRuntime}
	dev := mustNode("pkg:npm/jest@29.0.0")
	dev.Scopes = []model.Scope{model.ScopeDevelopment}
	unscoped := mustNode("pkg:npm/lodash@4.17.21")
	for _, node := range []*model.DependencyNode{runtime, dev, unscoped} {
		_ = g.AddNode(node)
	}

	filtered, report, err := model.FilterGraphByScopeWithReport(g, model.ScopeRuntime)
	if err != nil {
		panic(err)
	}
	for _, dep := range filtered.DependencyNodes() {
		fmt.Println(dep.NodeID())
	}
	fmt.Println("kept on absence:", len(report.Unasserted))
	// Output:
	// pkg:npm/lodash@4.17.21
	// pkg:npm/react@18.2.0
	// kept on absence: 1
}

// Compare reports what changed between two graphs, pairing version bumps.
func ExampleCompare() {
	base, head := model.New(), model.New()
	_ = base.AddNode(mustNode("pkg:npm/react@18.2.0"))
	_ = base.AddNode(mustNode("pkg:npm/left-pad@1.3.0"))
	_ = head.AddNode(mustNode("pkg:npm/react@18.3.0"))
	_ = head.AddNode(mustNode("pkg:npm/zod@3.0.0"))

	diff := model.Compare(base, head)
	for _, change := range diff.Updated {
		fmt.Println("updated:", change.Before.NodeID(), "->", change.After.NodeID())
	}
	for _, node := range diff.Added {
		fmt.Println("added:", node.NodeID())
	}
	for _, node := range diff.Removed {
		fmt.Println("removed:", node.NodeID())
	}
	// Output:
	// updated: pkg:npm/react@18.2.0 -> pkg:npm/react@18.3.0
	// added: pkg:npm/zod@3.0.0
	// removed: pkg:npm/left-pad@1.3.0
}
