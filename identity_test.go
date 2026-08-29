package sdk

import "testing"

func TestPackageIdentityDerivation(t *testing.T) {
	cases := []struct {
		name   string
		coords Coordinates
		want   string
	}{
		{
			name:   "purl derivable from ecosystem coordinates",
			coords: Coordinates{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM, Type: PackageTypePackage, Name: "Left-Pad", Version: "1.3.0"},
			want:   "pkg:npm/left-pad@1.3.0",
		},
		{
			name:   "existing purl wins and qualifiers are filtered by the identity allowlist",
			coords: Coordinates{PURL: "pkg:maven/g/a@1?type=jar"},
			want:   "pkg:maven/g/a@1",
		},
		{
			name:   "subpath survives the identity form",
			coords: Coordinates{PURL: "pkg:golang/example.com/mod@v1.0.0#internal/tool"},
			want:   "pkg:golang/example.com/mod@v1.0.0#internal/tool",
		},
		{
			name:   "manifest nodes take the coordinate fallback",
			coords: Coordinates{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM, Type: PackageTypeManifest, Name: "package.json"},
			want:   "coord:npm/npm/manifest//package.json/",
		},
		{
			name:   "fallback escapes hostile bytes in fields",
			coords: Coordinates{Type: PackageTypeManifest, Ecosystem: EcosystemNPM, Name: "my app/manifest.json"},
			want:   "coord:npm//manifest//my%20app%2Fmanifest.json/",
		},
		{
			name:   "empty coordinates have no identity",
			coords: Coordinates{},
			want:   "",
		},
	}
	for _, tc := range cases {
		if got := tc.coords.PackageIdentity(); got != tc.want {
			t.Errorf("%s: PackageIdentity() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestPackageIdentityIsEcosystemQualified(t *testing.T) {
	// The deprecated StableID's headline defect: npm and PyPI left-pad@1.0.0
	// collide. PackageIdentity keeps them apart.
	npm := Coordinates{Ecosystem: EcosystemNPM, Name: "left-pad", Version: "1.0.0"}
	pypi := Coordinates{Ecosystem: EcosystemPython, Name: "left-pad", Version: "1.0.0"}
	if npm.StableID() != pypi.StableID() {
		t.Fatal("test premise broken: StableID no longer collides across ecosystems")
	}
	if npm.PackageIdentity() == pypi.PackageIdentity() {
		t.Fatalf("PackageIdentity collides across ecosystems: %q", npm.PackageIdentity())
	}
}

func TestPackageIdentityMutatesNothing(t *testing.T) {
	dep := Dependency{Coordinates: Coordinates{Ecosystem: EcosystemNPM, Name: "  Left-Pad  ", Version: " 1.3.0 "}}
	if got := dep.PackageIdentity(); got != "pkg:npm/left-pad@1.3.0" {
		t.Fatalf("PackageIdentity() = %q", got)
	}
	if dep.Name != "  Left-Pad  " || dep.Version != " 1.3.0 " {
		t.Fatalf("PackageIdentity mutated the receiver: %+v", dep.Coordinates)
	}
	if dep.Metadata != nil {
		t.Fatalf("PackageIdentity stamped normalization metadata: %v", dep.Metadata)
	}
	var nilDep *Dependency
	if nilDep.PackageIdentity() != "" {
		t.Fatal("nil PackageIdentity must be empty")
	}
}

func TestNewDependencyDerivesIdentityIDs(t *testing.T) {
	dep := NewDependency(Dependency{Coordinates: Coordinates{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM, Name: "left-pad", Version: "1.3.0"}})
	if dep.ID != "pkg:npm/left-pad@1.3.0" {
		t.Fatalf("NewDependency ID = %q, want the canonical package URL", dep.ID)
	}
	ref := NewDependencyRef("lodash", "1.0.0")
	if ref.ID != "pkg:generic/lodash@1.0.0" {
		t.Fatalf("NewDependencyRef ID = %q, want the generic-type package URL", ref.ID)
	}
	empty := NewDependency(Dependency{})
	if empty.ID != "" {
		t.Fatalf("NewDependency with no identity minted %q", empty.ID)
	}
}

func TestOccurrenceFacetAndContentAddress(t *testing.T) {
	dep := NewDependency(Dependency{Coordinates: Coordinates{PURL: "pkg:npm/left-pad@1.3.0"}})
	if dep.OccurrenceFacet() != "" {
		t.Fatal("a fresh node must carry the default (empty) occurrence facet")
	}
	// Pinned against the identitykit golden vector "purl-empty-facet".
	if got := dep.ContentAddress(); got != "62b325a01a10705a6dd3235895830e1c" {
		t.Fatalf("ContentAddress() = %q, want the golden-vector address", got)
	}
	// Pinned against the golden vector "first-party-sentinel".
	app := NewDependency(Dependency{Coordinates: Coordinates{PURL: "pkg:npm/app@1.0.0"}})
	app.occurrenceFacet = FirstPartyOccurrenceFacet
	if got := app.ContentAddress(); got != "ac557298ddbd3057e821132f7983fd4a" {
		t.Fatalf("first-party ContentAddress() = %q, want the golden-vector address", got)
	}
	// The facet survives Clone via the struct copy the field comment pins.
	if clone := app.Clone(); clone.OccurrenceFacet() != FirstPartyOccurrenceFacet {
		t.Fatal("Clone dropped the occurrence facet")
	}
	var nilDep *Dependency
	if nilDep.OccurrenceFacet() != "" || nilDep.ContentAddress() != "" {
		t.Fatal("nil accessors must return empty values")
	}
}

func TestIdentityOriginFacet(t *testing.T) {
	// Admission derives only from the codec-surviving normalized origin: a
	// tokenized artifact query fails ADR-0033 normalization outright, so
	// such an origin admits nothing — after the JSON codec drops it, a
	// re-derivation reaches the same answer, keeping facets wire-stable,
	// and the credential bytes can never shape an identity.
	tokenized := &DependencyOrigin{ArtifactURL: "https://example.com/dl.tgz?X-Amz-Signature=secret123"}
	if facet, ok := identityOriginFacet(tokenized); ok {
		t.Fatalf("query-carrying artifact origin admitted facet %q", facet)
	}
	// Fragments are dropped by normalization, so the facet still admits.
	fragment := &DependencyOrigin{ArtifactURL: "https://example.com/dl.tgz#sha256=abc"}
	if facet, ok := identityOriginFacet(fragment); !ok || facet != "artifact\x00https://example.com/dl.tgz" {
		t.Fatalf("fragment artifact facet = (%q, %v)", facet, ok)
	}
	// Repository origins carry the validated revision as the third field.
	repo := &DependencyOrigin{Repository: "https://github.com/golang/text", Revision: "v0.3.5"}
	if facet, ok := identityOriginFacet(repo); !ok || facet != "repository\x00https://github.com/golang/text\x00v0.3.5" {
		t.Fatalf("repository facet = (%q, %v)", facet, ok)
	}
	// An invalid revision leaves an empty trailing field, still delimited.
	badRev := &DependencyOrigin{Repository: "https://github.com/golang/text", Revision: "has space"}
	if facet, ok := identityOriginFacet(badRev); !ok || facet != "repository\x00https://github.com/golang/text\x00" {
		t.Fatalf("invalid-revision facet = (%q, %v)", facet, ok)
	}
	// Unpublishable origins admit nothing.
	for name, origin := range map[string]*DependencyOrigin{
		"nil":        nil,
		"empty":      {},
		"local path": {ArtifactURL: "file:///home/user/dl.tgz"},
		"credential": {Repository: "https://user:pass@github.com/x/y"},
	} {
		if facet, ok := identityOriginFacet(origin); ok {
			t.Errorf("%s origin admitted facet %q", name, facet)
		}
	}
}

func TestPackageIdentityFoldsDiscriminatorSpellings(t *testing.T) {
	// The wire accepts case variants of the closed vocabularies verbatim, so
	// the fallback discriminators fold: "NPM" from a JSON payload and a
	// built-in's "npm" must mint one identity, or the same manifest node
	// never consolidates.
	upper := Coordinates{Ecosystem: "NPM", Type: "Manifest", Name: "package.json"}
	lower := Coordinates{Ecosystem: EcosystemNPM, Type: PackageTypeManifest, Name: "package.json"}
	if upper.PackageIdentity() != lower.PackageIdentity() {
		t.Fatalf("case-variant discriminators split identity: %q vs %q", upper.PackageIdentity(), lower.PackageIdentity())
	}
	if got := upper.PackageIdentity(); got != "coord:npm//manifest//package.json/" {
		t.Fatalf("folded fallback rendering = %q", got)
	}
	// The alias table also fills a missing ecosystem discriminator from the
	// package manager, so a pm-only producer renders the canonical ecosystem.
	bun := Coordinates{PackageManager: PackageManager("bun"), Type: PackageTypeManifest, Name: "package.json"}
	if got := bun.PackageIdentity(); got != "coord:npm/bun/manifest//package.json/" {
		t.Fatalf("alias-derived ecosystem rendering = %q", got)
	}
}
