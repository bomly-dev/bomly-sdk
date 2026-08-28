package purlkit

import "testing"

func TestSplitEcosystemName(t *testing.T) {
	cases := []struct {
		name      string
		ecosystem string
		input     string
		wantOrg   string
		wantName  string
	}{
		{"npm scoped", "npm", "@tailwindcss/postcss", "tailwindcss", "postcss"},
		{"npm bare", "npm", "postcss", "", "postcss"},
		{"npm bare with slash keeps whole", "npm", "weird/name", "", "weird/name"},
		{"npm scope without slash", "npm", "@scope", "", "@scope"},
		{"npm via alias", "pnpm", "@a/b", "a", "b"},
		{"maven", "maven", "org.apache.commons:commons-text", "org.apache.commons", "commons-text"},
		{"maven bare", "maven", "commons-text", "", "commons-text"},
		{"scala", "scala", "org.typelevel:cats-core", "org.typelevel", "cats-core"},
		{"go multi-segment", "go", "github.com/google/uuid", "github.com/google", "uuid"},
		{"go deep namespace", "go", "cloud.google.com/go/auth/internal", "cloud.google.com/go/auth", "internal"},
		{"go bare", "go", "uuid", "", "uuid"},
		{"php", "php", "symfony/console", "symfony", "console"},
		{"swift", "swift", "github.com/apple/swift-log", "github.com/apple", "swift-log"},
		{"github actions", "github-actions", "actions/checkout", "actions", "checkout"},
		// Outside the join list the whole input is the name: for OS packages
		// the org is a distro, never part of the package name (ADR-0021).
		{"apk keeps whole", "apk", "alpine/libcrypto3", "", "alpine/libcrypto3"},
		{"python keeps whole", "python", "requests", "", "requests"},
		{"unknown ecosystem", "does-not-exist", "a/b", "", "a/b"},
		{"empty name", "npm", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			org, name := SplitEcosystemName(tc.ecosystem, tc.input)
			if org != tc.wantOrg || name != tc.wantName {
				t.Fatalf("SplitEcosystemName(%q, %q) = (%q, %q), want (%q, %q)",
					tc.ecosystem, tc.input, org, name, tc.wantOrg, tc.wantName)
			}
		})
	}
}
