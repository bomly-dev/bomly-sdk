package sdk

import "testing"

// The gap this constructor closes, stated as the two calls it makes
// indistinguishable in correctness rather than in convenience.
//
// The swift ecosystem covers SwiftPM and CocoaPods. purlkit has no "swift"
// case -- swift is itself a purl type -- so the package manager is what
// separates the two. Hand PackageURLTypeForValues only the ecosystem and
// CocoaPods packages mint as pkg:swift: wrong ecosystem, no advisory matches,
// and a call site that looks right.
func TestBuildPackageURLForNeedsBothTokensToBeCorrect(t *testing.T) {
	const name, version = "Alamofire", "5.9.1"

	// pkg:swift requires a namespace and pkg:cocoapods forbids one -- the
	// spec's own per-type rules, which is a second reason the two cannot
	// share a call site. Each is given what its type demands.
	cocoapods := BuildPackageURLFor(EcosystemSwift, PackageManagerCocoaPods, "", name, version)
	swiftpm := BuildPackageURLFor(EcosystemSwift, PackageManagerSwiftPM, "github.com/Alamofire", name, version)

	if cocoapods == swiftpm {
		t.Fatalf("CocoaPods and SwiftPM both mint %q; the package manager is not reaching the mapping "+
			"and one ecosystem's packages are wearing the other's identity", cocoapods)
	}
	if want := "pkg:cocoapods/" + name + "@" + version; cocoapods != want {
		t.Errorf("cocoapods = %q, want %q", cocoapods, want)
	}
	if want := "pkg:swift/github.com/Alamofire/" + name + "@" + version; swiftpm != want {
		t.Errorf("swiftpm = %q, want %q", swiftpm, want)
	}

	// The shape this function exists to make unreachable: the ecosystem
	// alone answers "swift" for both, which is right for one and wrong for
	// the other. Asserted so the hazard is recorded, not just avoided.
	if alone := PackageURLTypeForValues(EcosystemSwift); alone != "swift" {
		t.Errorf("PackageURLTypeForValues(EcosystemSwift) = %q, want \"swift\"; the premise of this "+
			"constructor is that one token is not enough, and that premise just changed", alone)
	}
}

// Every ecosystem a detector mints for keeps the identity it had before this
// constructor existed, so adopting it is not a silent re-identification.
func TestBuildPackageURLForMatchesTheTypeItReplaces(t *testing.T) {
	for _, testCase := range []struct {
		ecosystem Ecosystem
		manager   PackageManager
		want      string
	}{
		{EcosystemPython, PackageManagerPip, "pkg:pypi/pkg@1"},
		{EcosystemPython, PackageManagerPoetry, "pkg:pypi/pkg@1"},
		{EcosystemRust, PackageManagerCargo, "pkg:cargo/pkg@1"},
		{EcosystemPHP, PackageManagerComposer, "pkg:composer/pkg@1"},
		{EcosystemElixir, PackageManagerMix, "pkg:hex/pkg@1"},
		{EcosystemDotNet, PackageManagerNuGet, "pkg:nuget/pkg@1"},
		{EcosystemCPP, PackageManagerConan, "pkg:conan/pkg@1"},
		{EcosystemScala, PackageManagerSBT, "pkg:maven/pkg@1"},
		{EcosystemDart, PackageManagerPub, "pkg:pub/pkg@1"},
		{EcosystemSwift, PackageManagerCocoaPods, "pkg:cocoapods/pkg@1"},
		// swift alone among these requires a namespace; the table gives it
		// one rather than pretending the types are uniform.
		{EcosystemSwift, PackageManagerSwiftPM, "pkg:swift/ns/pkg@1"},
	} {
		namespace := ""
		if testCase.manager == PackageManagerSwiftPM {
			namespace = "ns"
		}
		if got := BuildPackageURLFor(testCase.ecosystem, testCase.manager, namespace, "pkg", "1"); got != testCase.want {
			t.Errorf("%s/%s = %q, want %q", testCase.ecosystem, testCase.manager, got, testCase.want)
		}
	}
}

// An unknown pair still mints something rather than nothing, because the type
// vocabulary is open (ADR-0041): a detector for an ecosystem purlkit has never
// heard of expresses itself as its own purl type.
func TestBuildPackageURLForKeepsTheVocabularyOpen(t *testing.T) {
	if got := BuildPackageURLFor("pokemon", "", "", "pikachu", "25"); got != "pkg:pokemon/pikachu@25" {
		t.Errorf("an unknown ecosystem minted %q; the type vocabulary is open and a custom type is "+
			"first-class, not an error", got)
	}
}
