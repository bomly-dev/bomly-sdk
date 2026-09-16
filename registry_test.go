package sdk

import "testing"

func TestPackageRegistryUsesPURLAsDefaultPackageID(t *testing.T) {
	const purl = "pkg:npm/react@18.2.0"
	registry := NewPackageRegistry()

	ensured := registry.Ensure(purl)
	if ensured == nil {
		t.Fatal("Ensure() returned nil")
	}
	if ensured.ID != purl {
		t.Fatalf("Ensure() package ID = %q, want %q", ensured.ID, purl)
	}

	added := registry.Add(&Package{Coordinates: Coordinates{PURL: purl}})
	if added == nil {
		t.Fatal("Add() returned nil")
	}
	if added.ID != purl {
		t.Fatalf("Add() package ID = %q, want %q", added.ID, purl)
	}
}

func TestApplyPackageUpdates(t *testing.T) {
	registry := NewPackageRegistry()
	base := registry.Ensure("pkg:npm/left-pad@1.3.0")
	base.Name = "left-pad"

	updated := ApplyPackageUpdates(registry, []*Package{
		{Coordinates: Coordinates{PURL: "pkg:npm/left-pad@1.3.0"}, Licenses: []PackageLicense{{Value: "MIT"}}},
		{Coordinates: Coordinates{PURL: "pkg:npm/is-even@1.0.0"}},
		nil,
		{}, // no PURL: ignored
	})
	if updated != registry {
		t.Fatal("expected the same registry back")
	}
	merged, ok := registry.Get("pkg:npm/left-pad@1.3.0")
	if !ok || merged.Name != "left-pad" || len(merged.Licenses) != 1 {
		t.Fatalf("expected merged package to keep name and gain license: %+v", merged)
	}
	if _, ok := registry.Get("pkg:npm/is-even@1.0.0"); !ok {
		t.Fatal("expected new package to be added")
	}
	if got := len(registry.All()); got != 2 {
		t.Fatalf("expected 2 packages, got %d", got)
	}

	if reg := ApplyPackageUpdates(nil, nil); reg != nil {
		t.Fatal("nil registry with no updates should stay nil")
	}
	if reg := ApplyPackageUpdates(nil, []*Package{{Coordinates: Coordinates{PURL: "pkg:npm/a@1.0.0"}}}); reg == nil || len(reg.All()) != 1 {
		t.Fatal("nil registry with updates should allocate")
	}
}
