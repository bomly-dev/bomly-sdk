package purlkit

import (
	"strings"
	"testing"
)

func TestEvidenceQualifierKeys(t *testing.T) {
	want := []string{"download_url", "repository_url", "vcs_url"}
	got := EvidenceQualifierKeys()
	if len(got) != len(want) {
		t.Fatalf("EvidenceQualifierKeys() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("EvidenceQualifierKeys() = %v, want %v", got, want)
		}
	}
	if !IsEvidenceQualifierKey("Repository_URL") {
		t.Fatal("IsEvidenceQualifierKey must compare case-insensitively")
	}
	if IsEvidenceQualifierKey("arch") || IsEvidenceQualifierKey("distro") || IsEvidenceQualifierKey("checksum") {
		t.Fatal("identity qualifiers misclassified as evidence")
	}
}

func TestSplitIdentity(t *testing.T) {
	parsed, err := Parse("pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie&repository_url=https://deb.debian.org/debian&vcs_url=git%2Bhttps://example.com/curl.git")
	if err != nil {
		t.Fatal(err)
	}
	split := SplitIdentity(parsed)
	if got := split.Identity.String(); got != "pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie" {
		t.Fatalf("identity half = %q — arch and distro are identity, the URL-valued keys are not", got)
	}
	if len(split.Evidence) != 2 {
		t.Fatalf("evidence half = %+v, want repository_url and vcs_url", split.Evidence)
	}
	for _, qualifier := range split.Evidence {
		if !IsEvidenceQualifierKey(qualifier.Key) {
			t.Fatalf("non-evidence key %q relocated", qualifier.Key)
		}
	}
	// Custom qualifiers on custom types are identity: the open vocabulary.
	custom, err := Parse("pkg:pokemon/pikachu@25?region=kanto&shiny=true")
	if err != nil {
		t.Fatal(err)
	}
	customSplit := SplitIdentity(custom)
	if len(customSplit.Evidence) != 0 || len(customSplit.Identity.Qualifiers) != 2 {
		t.Fatalf("custom qualifiers must stay identity: %+v", customSplit)
	}
}

func TestIdentityForm(t *testing.T) {
	cases := map[string]string{
		"pkg:npm/left-pad@1.3.0?repository_url=https://registry.npmjs.org":              "pkg:npm/left-pad@1.3.0",
		"pkg:apk/alpine/musl@1.2.5?arch=x86_64":                                         "pkg:apk/alpine/musl@1.2.5?arch=x86_64",
		"pkg:golang/example.com/mod@v1.0.0#internal/tool":                               "pkg:golang/example.com/mod@v1.0.0#internal/tool",
		"pkg:maven/g/a@1?classifier=sources&download_url=https://repo1.maven.org/a.jar": "pkg:maven/g/a@1?classifier=sources",
		"not a purl": "",
		"":           "",
	}
	for input, want := range cases {
		if got := IdentityForm(input); got != want {
			t.Errorf("IdentityForm(%q) = %q, want %q", input, got, want)
		}
	}
	// Two architectures of one package keep distinct identity forms — the
	// container-scan collision the identity form must never introduce.
	amd := IdentityForm("pkg:apk/alpine/musl@1.2.5?arch=x86_64")
	arm := IdentityForm("pkg:apk/alpine/musl@1.2.5?arch=aarch64")
	if amd == arm || amd == "" {
		t.Fatalf("architecture qualifiers collapsed: %q vs %q", amd, arm)
	}
	if strings.Contains(IdentityForm("pkg:npm/a@1?download_url=https://e.com/a.tgz%3Ftoken%3Dsecret123"), "secret123") {
		t.Fatal("evidence qualifier bytes reached the identity form")
	}
}
