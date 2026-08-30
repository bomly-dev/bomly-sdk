package sdk

import (
	"reflect"
	"testing"
)

func TestNormalizePackageIdentityPython(t *testing.T) {
	coords := Coordinates{Ecosystem: EcosystemPython, Name: " Requests_Toolbelt ", Version: "1.0.0RC1"}

	// NormalizeDependencyIdentity is gone: NormalizeCoordinates returns the
	// applied rules, and the constructors record the provenance breadcrumbs.
	applied := NormalizeCoordinates(&coords)
	if !reflect.DeepEqual(applied, []string{"name", "version"}) {
		t.Fatalf("NormalizeCoordinates() applied = %#v", applied)
	}

	pkg := mustDep(t, Coordinates{Ecosystem: EcosystemPython, Name: " Requests_Toolbelt ", Version: "1.0.0RC1"})
	if pkg.Name != "requests-toolbelt" {
		normReturnNameMismatch(t, pkg.Name, "requests-toolbelt")
	}
	if pkg.Version != "1.0.0rc1" {
		normReturnNameMismatch(t, pkg.Version, "1.0.0rc1")
	}
	normAssertAppliedMetadata(t, pkg.Metadata, []string{"name", "version"})
}

func TestNormalizePackageIdentityRust(t *testing.T) {
	pkg := mustDep(t, Coordinates{PackageManager: PackageManagerCargo, Name: "Serde_JSON", Version: "1.0.0-RC1"})

	if pkg.Name != "serde-json" {
		normReturnNameMismatch(t, pkg.Name, "serde-json")
	}
	if pkg.Version != "1.0.0-rc1" {
		normReturnNameMismatch(t, pkg.Version, "1.0.0-rc1")
	}
	normAssertAppliedMetadata(t, pkg.Metadata, []string{"name", "version"})
}

func TestNormalizePackageIdentityNPMScopedName(t *testing.T) {
	pkg := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "@Types/Node", Version: "20.11.30"})

	if pkg.Org != "types" {
		normReturnNameMismatch(t, pkg.Org, "types")
	}
	if pkg.Name != "node" {
		normReturnNameMismatch(t, pkg.Name, "node")
	}
	normAssertAppliedMetadata(t, pkg.Metadata, []string{"npm-scope", "org", "name"})
}

func TestNormalizePackageIdentityGoPath(t *testing.T) {
	pkg := mustDep(t, Coordinates{Ecosystem: EcosystemGo, Name: "github.com\\Example\\lib//v2", Version: "V2.1.0-RC1"})

	// The identity splits a Go module path at its trailing segment, so the
	// module path is read back through the ecosystem-native accessor rather
	// than the bare Name field (ADR-0021). It is lowercased because the
	// purl specification's golang type says so and the library applies that
	// rule — identity delegates type semantics rather than keeping a second
	// opinion (ADR-0041).
	if got := pkg.EcosystemName(); got != "github.com/example/lib/v2" {
		normReturnNameMismatch(t, got, "github.com/example/lib/v2")
	}
	if pkg.Version != "v2.1.0-rc1" {
		normReturnNameMismatch(t, pkg.Version, "v2.1.0-rc1")
	}
	normAssertAppliedMetadata(t, pkg.Metadata, []string{"name", "version"})
}

func TestNormalizePackageIdentityUsesCanonicalEcosystemAliases(t *testing.T) {
	tests := []struct {
		name    string
		manager PackageManager
		input   string
		want    string
	}{
		{name: "bun uses npm rules", manager: PackageManagerBun, input: "PACKage", want: "package"},
		{name: "pdm uses python rules", manager: PackageManagerPDM, input: "Requests_Toolbelt", want: "requests-toolbelt"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkg := mustDep(t, Coordinates{PackageManager: tc.manager, Name: tc.input})

			if pkg.Name != tc.want {
				normReturnNameMismatch(t, pkg.Name, tc.want)
			}
		})
	}
}

func normAssertAppliedMetadata(t *testing.T, metadata map[string]any, want []string) {
	t.Helper()
	if metadata == nil {
		t.Fatal("expected metadata to be recorded")
	}
	got, ok := metadata[normMetadataAppliedKey].([]string)
	if !ok {
		t.Fatalf("expected %q metadata to be []string, got %#v", normMetadataAppliedKey, metadata[normMetadataAppliedKey])
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected normalization metadata %#v, got %#v", want, got)
	}
}

func normReturnNameMismatch(t *testing.T, got, want string) {
	t.Helper()
	t.Fatalf("expected %q, got %q", want, got)
}
