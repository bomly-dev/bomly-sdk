package testkit_test

import (
	"testing"

	sdk "github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/testkit"
)

// Maven versions are case sensitive, so 1.0-SNAPSHOT and 1.0-snapshot are two
// versions. A label lookup that folded their case would hand a test the wrong
// dependency and let it assert happily against it -- the worst failure a test
// helper can have, because it makes a green run meaningless.
func TestFindNodeDoesNotFoldVersionCase(t *testing.T) {
	g := sdk.New()
	upper := testkit.MustDependencyCoords(t, sdk.Coordinates{
		Ecosystem: sdk.EcosystemMaven, Org: "com.acme", Name: "app", Version: "1.0-SNAPSHOT",
	})
	if err := g.AddNode(upper); err != nil {
		t.Fatal(err)
	}

	if found, ok := testkit.FindNode(g, "com.acme:app@1.0-SNAPSHOT"); !ok || found.NodeID() != upper.NodeID() {
		t.Fatalf("the label as written did not find its node: %v, %v", found, ok)
	}
	if found, ok := testkit.FindNode(g, "com.acme:app@1.0-snapshot"); ok {
		t.Fatalf("a differently-cased version matched %q; Maven versions are case sensitive", found.NodeID())
	}
	if testkit.NodeIs(upper, "com.acme:app@1.0-snapshot") {
		t.Fatal("NodeIs folded a case-sensitive version")
	}
}

// The loose spellings exist for pre-ADR-0041 labels that detectors minted with
// their own separators and kind prefixes. They resolve names, never versions.
func TestFindNodeResolvesDetectorLabelSpellings(t *testing.T) {
	g := sdk.New()
	composer := testkit.MustDependencyCoords(t, sdk.Coordinates{
		Ecosystem: sdk.EcosystemPHP, Org: "vendor", Name: "shared", Version: "3.4.5",
	})
	module := testkit.MustModuleNode(t, "apps/web/package.json", sdk.Coordinates{
		Ecosystem: sdk.EcosystemNPM, Name: "web", Version: "1.0.0",
	})
	manifest := testkit.MustManifestNode(t, "package-lock.json", sdk.ManifestKindPackageLockJSON)
	for _, node := range []sdk.GraphNode{composer, module, manifest} {
		if err := g.AddNode(node); err != nil {
			t.Fatal(err)
		}
	}

	for label, want := range map[string]string{
		"vendor:shared@3.4.5": composer.NodeID(),
		"vendor/shared@3.4.5": composer.NodeID(),
		"web@1.0.0":           module.NodeID(),
		"package-lock.json":   manifest.NodeID(),
		composer.NodeID():     composer.NodeID(),
	} {
		found, ok := testkit.FindNode(g, label)
		if !ok || found.NodeID() != want {
			t.Errorf("FindNode(%q) = %v, %v; want %q", label, found, ok, want)
		}
		if got := testkit.NodeID(g, label); got != want {
			t.Errorf("NodeID(%q) = %q, want %q", label, got, want)
		}
	}

	// A label nothing answers to comes back unchanged, so a lookup meant to
	// fail still fails with the label in the error.
	if got := testkit.NodeID(g, "absent@1.0.0"); got != "absent@1.0.0" {
		t.Errorf("NodeID(absent) = %q, want the label unchanged", got)
	}
}
