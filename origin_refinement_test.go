package sdk

import "testing"

// A detector that reads a manifest and then a lockfile asserts the same
// repository twice: once bare, once pinned. Publishing both leaves a
// component with a pinned and a floating VCS reference for one repository,
// and a consumer reading the first gets a floating reference to a pinned
// dependency.
func TestMergeOriginsDropsAnOriginItsRefinementSupersedes(t *testing.T) {
	const repository = "https://github.com/apple/swift-argument-parser.git"
	const revision = "f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b"

	bare := DependencyOrigin{Repository: repository}
	pinned := DependencyOrigin{Repository: repository, Revision: revision}

	for name, merged := range map[string][]DependencyOrigin{
		"refinement arrives second": MergeOrigins([]DependencyOrigin{bare}, []DependencyOrigin{pinned}),
		"refinement arrives first":  MergeOrigins([]DependencyOrigin{pinned}, []DependencyOrigin{bare}),
		"both in one side":          MergeOrigins([]DependencyOrigin{bare, pinned}, nil),
	} {
		t.Run(name, func(t *testing.T) {
			if len(merged) != 1 {
				t.Fatalf("origins = %+v, want the bare one superseded", merged)
			}
			if merged[0].Revision != revision {
				t.Fatalf("origins = %+v, want the pinned revision kept", merged)
			}
		})
	}
}

// Two genuinely different places both survive: that disagreement is the shape
// of a dependency-confusion signal, not something to resolve by picking one.
func TestMergeOriginsKeepsGenuinelyDifferentPlaces(t *testing.T) {
	a := DependencyOrigin{Repository: "https://github.com/a/helper", Revision: "aaaabbbbccccddddeeeeffff0000111122223333"}
	b := DependencyOrigin{Repository: "https://github.com/b/helper", Revision: "bbbbccccddddeeeeffff00001111222233334444"}

	if merged := MergeOrigins([]DependencyOrigin{a}, []DependencyOrigin{b}); len(merged) != 2 {
		t.Fatalf("origins = %+v, want both remotes kept", merged)
	}

	// Nor does a pinned repository supersede an unrelated artifact URL.
	artifact := DependencyOrigin{ArtifactURL: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}
	if merged := MergeOrigins([]DependencyOrigin{artifact}, []DependencyOrigin{a}); len(merged) != 2 {
		t.Fatalf("origins = %+v, want the artifact and the repository both kept", merged)
	}

	// And a bare repository with no refinement present stays.
	bare := DependencyOrigin{Repository: "https://github.com/a/helper"}
	if merged := MergeOrigins([]DependencyOrigin{bare}, nil); len(merged) != 1 {
		t.Fatalf("origins = %+v, want the unrefined repository kept", merged)
	}
}
