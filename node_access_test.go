package sdk

import "testing"

// A typed nil is the trap these accessors exist to close: comparing a
// GraphNode against nil is false for a (*DependencyNode)(nil), so a caller
// that checks `node != nil` and then reads a field panics.
func TestNodeAccessorsTolerateATypedNil(t *testing.T) {
	for name, node := range map[string]GraphNode{
		"untyped nil":    nil,
		"nil dependency": (*DependencyNode)(nil),
		"nil module":     (*ModuleNode)(nil),
		"nil manifest":   (*ManifestNode)(nil),
	} {
		t.Run(name, func(t *testing.T) {
			if !IsNilNode(node) {
				t.Fatal("IsNilNode did not recognize the nil")
			}
			if _, ok := NodeCoordinates(node); ok {
				t.Fatal("NodeCoordinates reported coordinates on a nil node")
			}
			if got := NodeDisplayName(node); got != "" {
				t.Fatalf("NodeDisplayName = %q, want empty", got)
			}
			if _, ok := AsDependencyNode(node); ok {
				t.Fatal("AsDependencyNode narrowed a nil node")
			}
			if IsProjectOwned(node) {
				t.Fatal("IsProjectOwned reported ownership for a nil node")
			}
		})
	}
}

// Each kind answers with what it actually has: a manifest is a file and has
// no coordinates, and its only name is its path.
func TestNodeAccessorsReadEachKind(t *testing.T) {
	dep, err := NewDependencyNode(Coordinates{Ecosystem: EcosystemNPM, Name: "left-pad", Version: "1.3.0"})
	if err != nil {
		t.Fatal(err)
	}
	module, err := NewModuleNode("package.json", Coordinates{Ecosystem: EcosystemNPM, Name: "app", Version: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := NewManifestNode("package-lock.json", ManifestKindPackageLockJSON)
	if err != nil {
		t.Fatal(err)
	}

	if coords, ok := NodeCoordinates(dep); !ok || coords.Name != "left-pad" {
		t.Fatalf("dependency coordinates = %+v, ok = %v", coords, ok)
	}
	if coords, ok := NodeCoordinates(module); !ok || coords.Name != "app" {
		t.Fatalf("module coordinates = %+v, ok = %v", coords, ok)
	}
	if _, ok := NodeCoordinates(manifest); ok {
		t.Fatal("a manifest reported coordinates; a file is not a package")
	}
	if got := NodeDisplayName(manifest); got != "package-lock.json" {
		t.Fatalf("manifest display name = %q, want its path", got)
	}
	if got := NodeVersion(dep); got != "1.3.0" {
		t.Fatalf("dependency version = %q", got)
	}

	// Ownership is the kind: a module is the project's own artifact, and a
	// dependency is a consumed package however it is typed.
	if !IsProjectOwned(module) {
		t.Fatal("a module node is not reported as the project's own")
	}
	if IsProjectOwned(dep) || IsProjectOwned(manifest) {
		t.Fatal("a dependency or manifest node was reported as the project's own")
	}

	// An application-typed import is still a consumed package: treating it as
	// owned is what kept such packages out of diffing and matching.
	appTyped, err := NewDependencyNode(Coordinates{
		Ecosystem: EcosystemNPM, Name: "create-app", Version: "2.0.0", Type: PackageTypeApplication,
	})
	if err != nil {
		t.Fatal(err)
	}
	if IsProjectOwned(appTyped) {
		t.Fatal("an application-typed dependency was reported as the project's own")
	}

	narrowed := DependencyNodesOf([]GraphNode{module, dep, manifest, nil})
	if len(narrowed) != 1 || narrowed[0] != dep {
		t.Fatalf("DependencyNodesOf = %v, want only the dependency node", narrowed)
	}
}

// A prototype's fields survive construction. The identity is minted from the
// coordinates; everything else the prototype states is carried over, which is
// the loss this constructor exists to prevent.
func TestNewDependencyNodeFromCarriesEveryStatedField(t *testing.T) {
	proto := DependencyNode{
		Coordinates:  Coordinates{Ecosystem: EcosystemNPM, Name: "left-pad", Version: "1.3.0"},
		Relationship: DependencyRelationshipDirect,
		Source:       DependencySourceRegistry,
		Scopes:       ScopesOf(ScopeRuntime),
		Locations:    []PackageLocation{{RealPath: "package-lock.json", AccessPath: "package-lock.json"}},
		CPEs:         []string{"cpe:2.3:a:left-pad:left-pad:1.3.0:*:*:*:*:*:*:*"},
		Digests:      []Digest{{Algorithm: "sha512", Value: "abc"}},
		Copyright:    "Copyright someone",
		FoundBy:      "npm-lockfile",
		ResolvedURL:  "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
		Description:  "pads a string",
		Homepage:     "https://example.com/left-pad",
		Supplier:     &Contact{Kind: ContactKindOrganization, Name: "Acme"},
		Metadata:     map[string]any{"npm": "yes"},
		Matched:      true,
		PackageRef:   "pkg:npm/left-pad@1.3.0",
	}

	node, err := NewDependencyNodeFrom(proto)
	if err != nil {
		t.Fatalf("NewDependencyNodeFrom() error = %v", err)
	}
	if node.NodeID() != "pkg:npm/left-pad@1.3.0" {
		t.Fatalf("identity = %q, want it minted from the coordinates", node.NodeID())
	}
	for field, ok := range map[string]bool{
		"Relationship": node.Relationship == proto.Relationship,
		"Source":       node.Source == proto.Source,
		"Scopes":       node.PrimaryScope() == ScopeRuntime,
		"Locations":    len(node.Locations) == 1,
		"CPEs":         len(node.CPEs) == 1,
		"Digests":      len(node.Digests) == 1 && node.Digests[0].Value == "abc",
		"Copyright":    node.Copyright == proto.Copyright,
		"FoundBy":      node.FoundBy == proto.FoundBy,
		"ResolvedURL":  node.ResolvedURL == proto.ResolvedURL,
		"Description":  node.Description == proto.Description,
		"Homepage":     node.Homepage == proto.Homepage,
		"Metadata":     node.Metadata["npm"] == "yes",
		"Matched":      node.Matched == proto.Matched,
		"PackageRef":   node.PackageRef == proto.PackageRef,
	} {
		if !ok {
			t.Errorf("%s did not survive construction", field)
		}
	}

	// Nothing aliases the prototype: a producer that reuses one -- which is
	// the reason this constructor takes one at all -- must not be able to
	// mutate a node it already built.
	proto.Digests[0].Value = "mutated"
	if node.Digests[0].Value != "abc" {
		t.Error("digests alias the prototype's slice")
	}
	proto.Metadata["npm"] = "mutated"
	if node.Metadata["npm"] != "yes" {
		t.Error("metadata aliases the prototype's map")
	}
	if proto.Supplier != nil && node.Supplier == proto.Supplier {
		t.Error("supplier aliases the prototype's contact")
	}
}

// PackageRef names the package a node matched, and a node's identity is that
// package's URL: the two cannot disagree. Carrying a prototype's stale value
// pointed the node at a different package, which is the entry enrichment then
// reads.
func TestNewDependencyNodeFromDerivesPackageRefFromTheIdentity(t *testing.T) {
	node, err := NewDependencyNodeFrom(DependencyNode{
		Coordinates: Coordinates{Ecosystem: EcosystemNPM, Name: "left-pad", Version: "1.3.0"},
		PackageRef:  "pkg:npm/some-other-package@9.9.9",
	})
	if err != nil {
		t.Fatalf("NewDependencyNodeFrom() error = %v", err)
	}
	if node.PackageRef != node.NodeID() {
		t.Fatalf("PackageRef = %q, want the node identity %q", node.PackageRef, node.NodeID())
	}
}

// A package whose own purl type cannot express its coordinates is typed
// loosely rather than dropped -- it is installed, it is in the artifact, and
// an inventory that omits it is wrong in a way a generic type is not. The
// warning is how a consumer tells the difference.
func TestIdentityFallsBackToGenericWithAWarning(t *testing.T) {
	// A SwiftPM registry pin: no repository, so no namespace, and the swift
	// purl type requires one.
	node, err := NewDependencyNode(Coordinates{
		Ecosystem: EcosystemSwift, Name: "internal-tools", Version: "2.0.0",
	})
	if err != nil {
		t.Fatalf("NewDependencyNode() error = %v, want a generic identity instead", err)
	}
	if node.NodeID() != "pkg:generic/internal-tools@2.0.0?bomly_source_type=swift" {
		t.Fatalf("identity = %q, want a generic package URL discriminated by the failed type", node.NodeID())
	}
	// The discriminator is identity-only. Coordinates are projected from the
	// identity verbatim, so putting it in the namespace made a bare Swift
	// package read as organization "swift" -- an organization no manifest
	// declared, reaching display and ecosystem lookups.
	if node.Org != "" {
		t.Fatalf("Org = %q, want the discriminator kept out of the coordinates", node.Org)
	}
	if node.EcosystemName() != "internal-tools" || node.DisplayName() != "internal-tools" {
		t.Fatalf("names = %q / %q, want the package's own name", node.EcosystemName(), node.DisplayName())
	}
	if node.Ecosystem != EcosystemSwift {
		t.Fatalf("ecosystem = %q, want it kept on the coordinates", node.Ecosystem)
	}
	var warned bool
	for _, warning := range node.NodeWarnings() {
		if warning.Code == NodeWarningGenericIdentity {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("no generic-identity warning; warnings = %+v", node.NodeWarnings())
	}

	// A bare Go module fails the same way -- the golang type requires a
	// namespace too -- and must not land on the same identity. Two
	// ecosystems folding into one node is worse than the loose type this
	// fallback accepts, so the failed type leads the namespace.
	goPackage, err := NewDependencyNode(Coordinates{
		Ecosystem: EcosystemGo, Name: "internal-tools", Version: "2.0.0",
	})
	if err != nil {
		t.Fatalf("NewDependencyNode(go) error = %v, want a generic identity instead", err)
	}
	if goPackage.NodeID() != "pkg:generic/internal-tools@2.0.0?bomly_source_type=golang" {
		t.Fatalf("go identity = %q, want the failed type as the discriminator", goPackage.NodeID())
	}
	if goPackage.NodeID() == node.NodeID() {
		t.Fatalf("two ecosystems folded onto one generic identity: %q", node.NodeID())
	}

	// A stated package URL is an assertion, not a hint: it is refused, never
	// replaced by a looser one the caller did not write.
	if _, err := NewDependencyNode(Coordinates{
		Ecosystem: EcosystemGo, Name: "internal-tools", Version: "2.0.0",
		PURL: "pkg:golang/internal-tools@2.0.0",
	}); err == nil {
		t.Fatal("a stated but invalid package URL was silently replaced with a generic one")
	}

	// The warning survives the wire. It is derived from the identity rather
	// than tracked through construction, because warnings are deliberately
	// not serialized: a decoded fallback arrives as a stated pkg:generic URL,
	// and without the discriminator nothing would mark it -- leaving a
	// consumer unable to tell a degraded identity from a genuinely generic
	// package, which is the whole signal.
	decoded, err := NewDependencyNodeFromPURL(node.NodeID())
	if err != nil {
		t.Fatalf("NewDependencyNodeFromPURL(%q) error = %v", node.NodeID(), err)
	}
	var decodedWarned bool
	for _, warning := range decoded.NodeWarnings() {
		if warning.Code == NodeWarningGenericIdentity {
			decodedWarned = true
		}
	}
	if !decodedWarned {
		t.Fatalf("the generic-identity warning did not survive a round trip; warnings = %+v", decoded.NodeWarnings())
	}

	// An ecosystem whose type profile is satisfied is untouched.
	typed, err := NewDependencyNode(Coordinates{
		Ecosystem: EcosystemSwift, Org: "apple", Name: "swift-argument-parser", Version: "1.3.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if typed.NodeID() != "pkg:swift/apple/swift-argument-parser@1.3.0" {
		t.Fatalf("identity = %q, want the swift-typed package URL", typed.NodeID())
	}
	for _, warning := range typed.NodeWarnings() {
		if warning.Code == NodeWarningGenericIdentity {
			t.Fatal("a satisfiable identity was reported as generic")
		}
	}
}

// A location holds a Position pointer and a Scopes slice. Copying only the
// outer slice left both aliasing the prototype, so mutating a position after
// construction reached into a node already built.
func TestNewDependencyNodeFromDeepCopiesLocations(t *testing.T) {
	proto := DependencyNode{
		Coordinates: Coordinates{Ecosystem: EcosystemNPM, Name: "left-pad", Version: "1.3.0"},
		Locations: []PackageLocation{{
			RealPath:   "package-lock.json",
			AccessPath: "package-lock.json",
			Position:   &SourcePosition{Line: 12},
			Scopes:     ScopesOf(ScopeRuntime),
		}},
	}

	node, err := NewDependencyNodeFrom(proto)
	if err != nil {
		t.Fatalf("NewDependencyNodeFrom() error = %v", err)
	}

	proto.Locations[0].Position.Line = 99
	proto.Locations[0].Scopes[0] = ScopeDevelopment

	if node.Locations[0].Position.Line != 12 {
		t.Errorf("position line = %d, want the prototype's position deep-copied", node.Locations[0].Position.Line)
	}
	if node.Locations[0].Scopes[0] != ScopeRuntime {
		t.Errorf("location scope = %q, want the prototype's scopes deep-copied", node.Locations[0].Scopes[0])
	}
}
