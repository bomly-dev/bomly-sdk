package model

import (
	"encoding/json"
	"fmt"
	"reflect"
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

func TestAddEntryPackagesGoesThroughAdd(t *testing.T) {
	registry := NewPackageRegistry()
	seeded := registry.Ensure("pkg:npm/a@1.0.0")
	seeded.Name = "a"
	registry.AddEntryPackages([]GraphEntry{
		{Packages: []*Package{
			{Coordinates: Coordinates{PURL: "pkg:npm/a@1.0.0"}, Vulnerabilities: []Vulnerability{{ID: "CVE-1", Source: "s"}}, Description: "  from the document  "},
			nil,
			{Coordinates: Coordinates{Name: "no-purl"}},
		}},
		{Packages: []*Package{{Coordinates: Coordinates{PURL: "pkg:npm/b@1.0.0"}, EOL: &PackageEOL{EOL: true}}}},
	})
	a, ok := registry.Get("pkg:npm/a@1.0.0")
	if !ok || a.Name != "a" || len(a.Vulnerabilities) != 1 || a.Description != "from the document" {
		t.Fatalf("entry facts did not fold onto the seeded package: %+v", a)
	}
	if b, ok := registry.Get("pkg:npm/b@1.0.0"); !ok || b.EOL == nil || !b.EOL.EOL {
		t.Fatalf("second entry's package missing: %+v", b)
	}
	if registry.Len() != 2 {
		t.Fatalf("Len() = %d, want 2 (nil and purl-less packages ignored)", registry.Len())
	}
	var nilRegistry *PackageRegistry
	nilRegistry.AddEntryPackages(nil)
}

// TestPackageRegistryCloneSharesNothing proves the clone holds the same
// packages in the same insertion order with no memory in common, in both
// directions of mutation.
func TestPackageRegistryCloneSharesNothing(t *testing.T) {
	source := NewPackageRegistry()
	for _, purl := range []string{"pkg:npm/b@1.0.0", "pkg:npm/a@1.0.0", "pkg:npm/c@1.0.0"} {
		source.Add(filledPackage(purl))
	}
	clone := source.Clone()
	if !reflect.DeepEqual(source, clone) {
		t.Fatal("clone differs from its source")
	}
	assertSharesNothing(t, source, clone)

	before, err := json.Marshal(source)
	if err != nil {
		t.Fatalf("marshal source: %v", err)
	}
	pkg, _ := clone.Get("pkg:npm/a@1.0.0")
	pkg.Vulnerabilities[0].ID = "CHANGED"
	pkg.Licenses = append(pkg.Licenses, PackageLicense{Value: "MIT"})
	clone.Ensure("pkg:npm/new@1.0.0")
	clone.Add(&Package{Coordinates: Coordinates{PURL: "pkg:npm/b@1.0.0"}, Matched: true, Vulnerabilities: []Vulnerability{{Source: "osv", ID: "GHSA-new"}}})
	after, err := json.Marshal(source)
	if err != nil {
		t.Fatalf("marshal source: %v", err)
	}
	if string(before) != string(after) {
		t.Error("mutating the clone changed the source registry")
	}

	again := source.Clone()
	source.Ensure("pkg:npm/late@1.0.0")
	if _, ok := again.Get("pkg:npm/late@1.0.0"); ok {
		t.Error("a package added to the source appeared in the clone")
	}

	if (*PackageRegistry)(nil).Clone() != nil {
		t.Error("a nil registry clones to non-nil")
	}
	if empty := NewPackageRegistry().Clone(); empty.Len() != 0 || empty.Ensure("pkg:npm/x@1.0.0") == nil {
		t.Error("an empty registry's clone is not a usable empty registry")
	}
}

// TestPackageRegistryCloneIsNotAJSONRoundTrip keeps the snapshot a host takes
// before every component call off the codec path. A round trip would
// normalize -- so the copy would not be the source -- and costs several
// times the allocations; the bound is loose enough to survive new fields and
// tight enough to fail if Clone were ever rewritten as Marshal+Unmarshal.
func TestPackageRegistryCloneIsNotAJSONRoundTrip(t *testing.T) {
	registry := NewPackageRegistry()
	for i := range 50 {
		registry.Add(enrichedPackage(i))
	}
	cloneAllocs := testing.AllocsPerRun(5, func() { _ = registry.Clone() })
	roundTripAllocs := testing.AllocsPerRun(5, func() {
		data, err := json.Marshal(registry)
		if err != nil {
			t.Fatal(err)
		}
		var decoded PackageRegistry
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
	})
	if cloneAllocs*2 > roundTripAllocs {
		t.Errorf("Clone allocates %.0f times against a JSON round trip's %.0f; it should be well under half", cloneAllocs, roundTripAllocs)
	}
}

// enrichedPackage is a package shaped like a matched one -- valid enums, a
// license, two advisories with an analysis, npm metadata -- that the codecs
// accept, so a round trip measures the codec rather than an early error.
func enrichedPackage(i int) *Package {
	return &Package{
		Coordinates: Coordinates{PURL: fmt.Sprintf("pkg:npm/dep-%d@1.0.0", i), Ecosystem: EcosystemNPM, Name: fmt.Sprintf("dep-%d", i), Version: "1.0.0"},
		Assertions: Assertions{
			Description: "a dependency",
			Licenses:    []PackageLicense{{Value: "MIT", SPDXExpression: "MIT", Type: LicenseTypeDeclared}},
			CPEs:        []string{"cpe:2.3:a:acme:dep:1.0.0:*:*:*:*:*:*:*"},
		},
		Vulnerabilities: []Vulnerability{
			{Source: "osv", ID: fmt.Sprintf("GHSA-%d-a", i), Summary: "first", Aliases: []string{"CVE-2024-1"}},
			{Source: "osv", ID: fmt.Sprintf("GHSA-%d-b", i), Summary: "second", DatabaseSpecific: map[string]any{"severity": "HIGH"}},
		},
		Matched:  true,
		Metadata: map[string]any{"nested": map[string]any{"list": []any{"a", "b"}}},
	}
}

func BenchmarkPackageRegistryClone(b *testing.B) {
	registry := NewPackageRegistry()
	for i := range 500 {
		registry.Add(enrichedPackage(i))
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = registry.Clone()
	}
}
