package purlkit

import (
	"errors"
	"strings"
	"testing"
)

func TestParseAndStringRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"simple", "pkg:npm/left-pad@1.0.0", "pkg:npm/left-pad@1.0.0"},
		{"npm scope", "pkg:npm/%40scope/name@2.0.0", "pkg:npm/%40scope/name@2.0.0"},
		{"qualifiers sorted", "pkg:deb/debian/curl@7.50.3-1?distro=jessie&arch=i386", "pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie"},
		{"subpath", "pkg:golang/github.com/google/go-github@v17.0.0#api", "pkg:golang/github.com/google/go-github@v17.0.0#api"},
		{"subpath no version", "pkg:golang/example.com/mod#sub/dir", "pkg:golang/example.com/mod#sub/dir"},
		{"type lowercased", "pkg:NPM/left-pad@1.0.0", "pkg:npm/left-pad@1.0.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := Parse(tc.input)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.input, err)
			}
			if got := parsed.String(); got != tc.want {
				t.Fatalf("Parse(%q).String() = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseRejectsInvalid(t *testing.T) {
	for _, input := range []string{"", "   ", "not-a-purl", "pkg:", "pkg:npm", "http://example.com"} {
		if _, err := Parse(input); err == nil {
			t.Fatalf("Parse(%q) succeeded, want error", input)
		}
	}
}

func TestBuildCarriesQualifiersAndSubpath(t *testing.T) {
	built, err := Build(PURL{
		Type:       "maven",
		Namespace:  "org.apache.commons",
		Name:       "commons-text",
		Version:    "1.10.0",
		Qualifiers: []Qualifier{{Key: "Type", Value: "jar"}, {Key: "classifier", Value: "sources"}},
		Subpath:    "docs",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	want := "pkg:maven/org.apache.commons/commons-text@1.10.0?classifier=sources&type=jar#docs"
	if built != want {
		t.Fatalf("Build = %q, want %q", built, want)
	}
}

func TestBuildRequiresTypeAndName(t *testing.T) {
	if _, err := Build(PURL{Type: "", Name: "x"}); err == nil {
		t.Fatal("Build without type succeeded")
	}
	if _, err := Build(PURL{Type: "npm", Name: ""}); err == nil {
		t.Fatal("Build without name succeeded")
	}
}

func TestBuildRestoresNPMScope(t *testing.T) {
	built, err := Build(PURL{Type: "npm", Namespace: "scope", Name: "pkg", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if want := "pkg:npm/%40scope/pkg@1.0.0"; built != want {
		t.Fatalf("Build = %q, want %q", built, want)
	}
}

func TestBaseIsStructural(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"version stripped", "pkg:npm/left-pad@1.0.0", "pkg:npm/left-pad"},
		{"qualifiers stripped", "pkg:deb/debian/curl@7.50.3-1?arch=i386", "pkg:deb/debian/curl"},
		// The legacy string surgery kept the subpath glued onto a
		// version-less package URL; the structural form strips it.
		{"subpath stripped without version", "pkg:golang/example.com/mod#sub", "pkg:golang/example.com/mod"},
		{"subpath stripped with version", "pkg:golang/example.com/mod@v1.2.3#sub", "pkg:golang/example.com/mod"},
		{"already base", "pkg:pypi/requests", "pkg:pypi/requests"},
		{"invalid", "not-a-purl", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Base(tc.input); got != tc.want {
				t.Fatalf("Base(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestCanonicalPrefersExisting(t *testing.T) {
	existing := "pkg:npm/left-pad@1.0.0"
	got := Canonical(existing, PURL{Type: "pypi", Name: "other"})
	if got != existing {
		t.Fatalf("Canonical kept %q, want existing %q", got, existing)
	}
}

func TestCanonicalBuildsFromPartsWithQualifiers(t *testing.T) {
	got := Canonical("not-a-purl", PURL{
		Type: "maven", Namespace: "g", Name: "a", Version: "1",
		Qualifiers: []Qualifier{{Key: "type", Value: "jar"}},
	})
	if want := "pkg:maven/g/a@1?type=jar"; got != want {
		t.Fatalf("Canonical = %q, want %q", got, want)
	}
}

func TestCanonicalizeMatchesLegacyBehavior(t *testing.T) {
	// Signature-compatibility cases for the root delegation: empty and
	// invalid inputs return "", valid inputs return the normalized form.
	if got := Canonicalize(""); got != "" {
		t.Fatalf("Canonicalize(empty) = %q", got)
	}
	if got := Canonicalize("  pkg:npm/a@1  "); got != "pkg:npm/a@1" {
		t.Fatalf("Canonicalize trimmed = %q", got)
	}
}

func TestParseErrorsMatchSentinel(t *testing.T) {
	// Every failure shape matches ErrInvalidPURL, including errors surfaced
	// by the underlying parser — callers classify with errors.Is alone.
	for _, input := range []string{"", "not-a-purl", "pkg:", "pkg:npm", "http://example.com"} {
		if _, err := Parse(input); !errors.Is(err, ErrInvalidPURL) {
			t.Errorf("Parse(%q) error %v does not match ErrInvalidPURL", input, err)
		}
	}
	if _, err := Build(PURL{}); !errors.Is(err, ErrInvalidPURL) {
		t.Errorf("Build(zero) error %v does not match ErrInvalidPURL", err)
	}
}

func TestParseBoundsOversizedInput(t *testing.T) {
	oversized := "pkg:npm/" + strings.Repeat("a", maxInputSize)
	if _, err := Parse(oversized); !errors.Is(err, ErrInvalidPURL) {
		t.Fatalf("oversized input error %v does not match ErrInvalidPURL", err)
	}
}
