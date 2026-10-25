package plugin

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/bomly-dev/bomly-sdk/internal/deepcopytest"
)

func TestAnalyzeRequestCloneSharesNothing(t *testing.T) {
	graph, registry, target := requestFixture(t)
	var source AnalyzeRequest
	deepcopytest.Fill(&source)
	source.Graph, source.Registry, source.Target = graph, registry, target
	source.Stderr = &bytes.Buffer{}

	clone := source.Clone()
	if !reflect.DeepEqual(source, clone) {
		t.Fatal("clone differs from its source")
	}
	assertRequestSharesNothing(t, source, clone)

	pkg, _ := clone.Registry.Get("pkg:npm/a@1.0.0")
	pkg.Vulnerabilities[0].Reachability = nil
	clone.AnalyzerFilter.Exclude[0] = "changed"
	if stored, _ := source.Registry.Get("pkg:npm/a@1.0.0"); stored.Vulnerabilities[0].Reachability == nil {
		t.Error("mutating the cloned registry changed the source")
	}
	if source.AnalyzerFilter.Exclude[0] == "changed" {
		t.Error("mutating the cloned filter changed the source")
	}

	var empty AnalyzeRequest
	if got := empty.Clone(); got.Graph != nil || got.Registry != nil || got.Target != nil {
		t.Error("a request without graph, registry or target clones to one with them")
	}
}
