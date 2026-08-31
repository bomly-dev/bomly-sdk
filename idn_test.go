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

// TestHostsThatMapToEmptyLabelsAreRefused pins a case the fuzzer found and a
// case review found. IDNA maps some code points away entirely -- a soft hyphen
// is ignorable -- so a label made only of those maps to nothing without an
// error. A host that is one such label converted to the empty string and
// published a URL with no host at all; a host with one such label among others
// converted to ".example" or "a..b" and published a name no resolver accepts.
func TestHostsThatMapToEmptyLabelsAreRefused(t *testing.T) {
	for _, raw := range []string{
		"https://\u00ad/x",       // the whole host maps away
		"https://\u00ad\u00ad/x", // ... in more than one code point
		"https://\u00ad:8443/x",  // ... with a port held back
		"https://\u00ad.example/x",
		"https://a.\u00ad.b/x",
		"https://example.\u00ad/x",
		"https://\u4f8b\u3048..\u30c6\u30b9\u30c8/x", // an empty label written literally
		"https://\u4f8b\u3048.\u30c6\u30b9\u30c8../x",
	} {
		if got, ok := NormalizeURL(raw, URLFormReference); ok {
			t.Errorf("%q was published as %q, which no resolver accepts", raw, got)
		}
	}
	// A bracketed host that is not an IP literal never reaches the
	// conversion: url.Parse refuses it first.
	if got, ok := NormalizeURL("https://[\u4f8b\u3048]/x", URLFormReference); ok {
		t.Errorf("a bracketed non-literal host was published as %q", got)
	}
}

// TestOverlongLabelsAreRefused pins the rest of what the library's length
// check buys: a label a resolver cannot carry is not a location to publish.
func TestOverlongLabelsAreRefused(t *testing.T) {
	// 63 bytes is the limit, and each of these characters costs more than one
	// byte in its punycode form, so 60 of them exceed it.
	long := strings.Repeat("\u4f8b", 60)
	if got, ok := NormalizeURL("https://"+long+".example/x", URLFormReference); ok {
		t.Errorf("an over-long label was published as %q", got)
	}
	// A label just inside the limit still publishes, so the check is a limit
	// and not a blanket refusal of long names.
	if _, ok := NormalizeURL("https://"+strings.Repeat("\u4f8b", 10)+".example/x", URLFormReference); !ok {
		t.Error("a label inside the length limit was refused")
	}
}

// TestTrailingDotHostsSurvive pins that an absolute name keeps publishing. A
// trailing dot is legal and resolvable, and an ASCII host carrying one takes
// the fast path untouched -- so refusing the Unicode spelling of a name whose
// ASCII spelling publishes would be an inconsistency introduced by the label
// check, not by anything wrong with the host.
func TestTrailingDotHostsSurvive(t *testing.T) {
	got, ok := NormalizeURL("https://"+idnHost+"./docs", URLFormReference)
	if !ok || got != "https://"+punyHost+"./docs" {
		t.Fatalf("got %q ok=%v, want the punycode host keeping its trailing dot", got, ok)
	}
	// With a port, both are held back and both come back.
	got, ok = NormalizeURL("https://"+idnHost+".:8443/docs", URLFormReference)
	if !ok || got != "https://"+punyHost+".:8443/docs" {
		t.Fatalf("got %q ok=%v, want the trailing dot and the port", got, ok)
	}
	// The ASCII spelling this parity exists for.
	if got, ok := NormalizeURL("https://example.com./docs", URLFormReference); !ok || got != "https://example.com./docs" {
		t.Fatalf("got %q ok=%v, want the ASCII trailing dot untouched", got, ok)
	}
	// Re-normalizing is stable: the dot survives the second pass too.
	once, _ := NormalizeURL("https://"+idnHost+"./docs", URLFormReference)
	if twice, ok := NormalizeURL(once, URLFormReference); !ok || twice != once {
		t.Fatalf("re-normalizing %q gave %q (ok=%v)", once, twice, ok)
	}
}
