package sdk

import "testing"

// PyPI holds "1.0.0RC1" and "1.0.0rc1" as one release: PEP 440 normalizes
// case and the pre-release spellings, and the index refuses to hold both. Two
// identities for the pair were two components for one package -- two matching
// results, duplicate vulnerabilities -- which is the duplicate-identity
// problem ADR-0041 exists to remove. v0.9.0 dropped the blanket lowercasing
// that folded this by accident (and corrupted Maven's 1.0-SNAPSHOT); this is
// the rule that replaces it, scoped to pypi and delegated to the library
// that owns the grammar.
func TestPyPIVersionFoldsToOneIdentity(t *testing.T) {
	upper := mustDep(t, Coordinates{Ecosystem: EcosystemPython, Name: "requests-toolbelt", Version: "1.0.0RC1"})
	lower := mustDep(t, Coordinates{Ecosystem: EcosystemPython, Name: "requests-toolbelt", Version: "1.0.0rc1"})
	if upper.NodeID() != lower.NodeID() {
		t.Fatalf("two identities for one PyPI release: %q and %q", upper.NodeID(), lower.NodeID())
	}
	if upper.NodeID() != "pkg:pypi/requests-toolbelt@1.0.0rc1" {
		t.Fatalf("identity = %q, want the PEP 440 canonical version", upper.NodeID())
	}

	// The coordinates say what the identity says -- the normalized version
	// replaces the stated one, as every other projection does -- and the
	// manifest's spelling survives in the provenance breadcrumb, so a reader
	// can still see what was written.
	if upper.Version != "1.0.0rc1" {
		t.Fatalf("Version = %q, want it projected from the identity", upper.Version)
	}
	if got := upper.Metadata[normMetadataOriginalVersionKey]; got != "1.0.0RC1" {
		t.Fatalf("original version breadcrumb = %v, want %q", got, "1.0.0RC1")
	}

	// Every path to an identity folds the same way: a stated package URL on
	// the coordinates, a raw package URL, and any Python package-manager
	// token, since they all mint the pypi type.
	for name, node := range map[string]*DependencyNode{
		"stated purl": mustDep(t, Coordinates{PURL: "pkg:pypi/requests-toolbelt@1.0.0RC1"}),
		"raw purl":    mustDepPURL(t, "pkg:pypi/Requests_Toolbelt@1.0.0.RC.1"),
		"poetry":      mustDep(t, Coordinates{PackageManager: PackageManagerPoetry, Name: "requests-toolbelt", Version: "1.0.0-rc1"}),
	} {
		if node.NodeID() != upper.NodeID() {
			t.Errorf("%s: identity = %q, want %q", name, node.NodeID(), upper.NodeID())
		}
	}

	// A version PEP 440 does not describe is left as written, and the
	// package is still constructed: an unconventional version is not a
	// reason to drop something that is installed.
	dated := mustDep(t, Coordinates{Ecosystem: EcosystemPython, Name: "internal", Version: "2021-03-01"})
	if dated.Version != "2021-03-01" || dated.NodeID() != "pkg:pypi/internal@2021-03-01" {
		t.Fatalf("unparseable version: Version = %q, id = %q; want both as written", dated.Version, dated.NodeID())
	}

	// The rule is pypi's alone. Maven versions are case sensitive, so
	// 1.0-SNAPSHOT must not become 1.0-snapshot -- that is the corruption
	// the blanket rule caused and v0.9.0 removed.
	maven := mustDep(t, Coordinates{Ecosystem: EcosystemMaven, Org: "org.example", Name: "lib", Version: "1.0-SNAPSHOT"})
	if maven.Version != "1.0-SNAPSHOT" || maven.NodeID() != "pkg:maven/org.example/lib@1.0-SNAPSHOT" {
		t.Fatalf("maven: Version = %q, id = %q; want the case kept", maven.Version, maven.NodeID())
	}
}
