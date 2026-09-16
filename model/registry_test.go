package model

import (
	"encoding/json"
	"strings"
	"testing"
)

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

// TestRegistryGatesArrivingAssertions pins the registry's door. Package has no
// JSON codec of its own and matcher package updates cross the plugin wire as
// plain structs, so without a gate at Add a matcher could put credentials or a
// control character straight into the registry, which PackageRegistry then
// forwards to every reader.
func TestRegistryGatesArrivingAssertions(t *testing.T) {
	registry := NewPackageRegistry()
	// The first record of a PURL takes the clone path, not the merge path.
	stored := registry.Add(&Package{
		Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"},
		Homepage:    "https://user:pw@react.test/",
		Description: "bad\x07text",
		Supplier:    &Contact{Kind: ContactKindOrganization, Name: "Acme\nInc"},
		Licenses:    []PackageLicense{{Value: "x", SPDXExpression: "not valid OR"}},
		Digests:     []Digest{{Algorithm: "crc32", Value: "zz"}, {Algorithm: DigestAlgorithmSHA256, Value: "abc"}},
	})
	if stored.Homepage != "" {
		t.Fatalf("credentials entered the registry: %q", stored.Homepage)
	}
	if stored.Description != "badtext" {
		t.Fatalf("description = %q, want the control character dropped", stored.Description)
	}
	if stored.Supplier != nil {
		t.Fatalf("an unpublishable supplier entered the registry: %+v", stored.Supplier)
	}
	if len(stored.Licenses) != 1 || stored.Licenses[0].SPDXExpression != "" {
		t.Fatalf("licenses = %+v, want the unparseable expression dropped", stored.Licenses)
	}
	if len(stored.Digests) != 1 || stored.Digests[0].Algorithm != DigestAlgorithmSHA256 {
		t.Fatalf("digests = %+v, want only the publishable one", stored.Digests)
	}

	// The merge path is gated too: a second update for the same PURL fills
	// gaps, and must not fill them with an unpublishable value.
	ApplyPackageUpdates(registry, []*Package{{
		Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"},
		Homepage:    "https://user:pw@evil.test/",
		Supplier:    &Contact{Kind: ContactKindOrganization, Name: "Bad\nActor"},
	}})
	merged, _ := registry.Get("pkg:npm/react@18.2.0")
	if merged.Homepage != "" || merged.Supplier != nil {
		t.Fatalf("a matcher update carried an unpublishable assertion into the registry: %+v", merged)
	}

	// A publishable update still fills the gap -- the gate rejects, it does
	// not simply refuse everything.
	ApplyPackageUpdates(registry, []*Package{{
		Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"},
		Homepage:    "https://react.test",
	}})
	merged, _ = registry.Get("pkg:npm/react@18.2.0")
	if merged.Homepage != "https://react.test" {
		t.Fatalf("homepage = %q, want the valid update to fill the gap", merged.Homepage)
	}
}

// TestRegistryMarshalReGatesMutatedRecords pins the second door. Add gates
// what comes in, but Ensure, Get, and All hand back mutable pointers and the
// established pattern is to mutate what Ensure returns, so an assertion
// installed after insertion would otherwise reach every reader unchecked.
func TestRegistryMarshalReGatesMutatedRecords(t *testing.T) {
	registry := NewPackageRegistry()
	registry.Add(&Package{Coordinates: Coordinates{PURL: "pkg:npm/react@18.2.0"}})
	stored := registry.Ensure("pkg:npm/react@18.2.0")
	stored.Homepage = "https://user:pw@evil.test/"
	stored.Description = "bad\x07text"
	stored.Supplier = &Contact{Kind: ContactKindOrganization, Name: "Acme\nInc"}

	encoded, err := json.Marshal(registry)
	if err != nil {
		t.Fatalf("encode registry: %v", err)
	}
	for _, forbidden := range []string{"user:pw", "\\u0007", `"supplier"`} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("encoded registry contains %s: %s", forbidden, encoded)
		}
	}
	// Normalizing the copy must not rewrite the record its holder still owns.
	if stored.Homepage != "https://user:pw@evil.test/" {
		t.Fatalf("marshal mutated the stored record: %q", stored.Homepage)
	}
}
