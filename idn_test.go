package sdk

import (
	"strings"
	"testing"
)

const idnHost = "\u4f8b\u3048.\u30c6\u30b9\u30c8"
const punyHost = "xn--r8jz45g.xn--zckzah"

// TestUnicodeHostsPublishAsPunycode pins the fix for a defect shipped in
// v0.6.0: url.URL renders a URI, so it percent-encodes the authority, and a
// Unicode host published as "https://%E4%BE%8B%E3%81%88.../docs" -- which no
// client resolves, because a host travels as punycode, not as escapes.
func TestUnicodeHostsPublishAsPunycode(t *testing.T) {
	for _, form := range []URLForm{URLFormArtifact, URLFormRepository, URLFormReference} {
		got, ok := NormalizeURL("https://"+idnHost+"/docs", form)
		if !ok {
			t.Fatalf("form %v rejected a valid IDN host", form)
		}
		if strings.Contains(got, "%") {
			t.Fatalf("form %v published a percent-encoded authority: %q", form, got)
		}
		if got != "https://"+punyHost+"/docs" {
			t.Fatalf("form %v = %q, want the punycode host", form, got)
		}
	}

	// The port survives: IDNA rejects a colon, so it has to be held back
	// rather than converted with the name.
	got, ok := NormalizeURL("https://"+idnHost+":8443/docs", URLFormReference)
	if !ok || got != "https://"+punyHost+":8443/docs" {
		t.Fatalf("got %q ok=%v, want the punycode host with its port", got, ok)
	}
	// A default port is still dropped, as before.
	if got, _ := NormalizeURL("https://"+idnHost+":443/docs", URLFormReference); got != "https://"+punyHost+"/docs" {
		t.Fatalf("got %q, want the default port dropped", got)
	}
}

// TestASCIIHostsAreUntouched pins the fast path. Only Unicode hosts change, so
// every existing origin and reference keeps the exact bytes it had.
func TestASCIIHostsAreUntouched(t *testing.T) {
	for _, raw := range []string{
		"https://registry.npmjs.org/react/-/react-18.2.0.tgz",
		"https://" + punyHost + "/docs", // already punycode
		"https://[2001:db8::1]/x",       // an IP literal has no punycode form
		"https://[2001:db8::1]:8443/x",
	} {
		got, ok := NormalizeURL(raw, URLFormReference)
		if !ok {
			t.Fatalf("%q was rejected", raw)
		}
		if got != raw {
			t.Fatalf("%q was rewritten to %q", raw, got)
		}
	}
}

// TestPunycodeConversionIsAFixedPoint pins that normalizing twice is stable:
// the rule runs on write and again on read.
func TestPunycodeConversionIsAFixedPoint(t *testing.T) {
	once, ok := NormalizeURL("https://"+idnHost+"/docs", URLFormReference)
	if !ok {
		t.Fatal("a valid IDN host was rejected")
	}
	twice, ok := NormalizeURL(once, URLFormReference)
	if !ok || twice != once {
		t.Fatalf("re-normalizing %q gave %q (ok=%v)", once, twice, ok)
	}
}

// TestOriginsCarryPunycodeHosts pins that the ADR-0033 constructors inherit
// the fix, since they are the reason this gate exists.
func TestOriginsCarryPunycodeHosts(t *testing.T) {
	artifact := ArtifactOrigin("https://" + idnHost + "/pkg.tgz")
	if artifact == nil || artifact.ArtifactURL != "https://"+punyHost+"/pkg.tgz" {
		t.Fatalf("artifact origin = %+v, want a punycode host", artifact)
	}
	repository := RepositoryOrigin("https://"+idnHost+"/owner/repo", "abc123")
	if repository == nil || repository.Repository != "https://"+punyHost+"/owner/repo" {
		t.Fatalf("repository origin = %+v, want a punycode host", repository)
	}
}

// TestHostsThatConvertToNothingAreRefused pins a case the fuzzer found. IDNA
// maps some code points away entirely -- a soft hyphen is ignorable -- so a
// host made only of those converts to an empty string with no error, and the
// emptiness check runs before the conversion. Without a second check the
// result was a URL with no host at all.
func TestHostsThatConvertToNothingAreRefused(t *testing.T) {
	for _, raw := range []string{
		"https://\u00ad/x",
		"https://\u00ad\u00ad/x",
		"https://\u00ad:8443/x",
	} {
		if got, ok := NormalizeURL(raw, URLFormReference); ok {
			t.Errorf("%q was published as %q, which has no host", raw, got)
		}
	}
	// A bracketed host that is not an IP literal never reaches the
	// conversion: url.Parse refuses it first.
	if got, ok := NormalizeURL("https://[\u4f8b\u3048]/x", URLFormReference); ok {
		t.Errorf("a bracketed non-literal host was published as %q", got)
	}
}
