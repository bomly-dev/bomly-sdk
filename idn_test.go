package sdk

import (
	"net/url"
	"strings"
	"testing"

	"golang.org/x/net/idna"
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
}

// TestBracketedHostsAreValidatedByTheParser states an assumption hostToASCII
// depends on but does not enforce. It skips the conversion for any bracketed
// host, on the grounds that brackets mean an IP literal -- which holds only
// because net/url validates the enclosed address with ParseAddr and refuses
// "https://[\u4f8b\u3048]/x" outright. That is the standard library's behavior, not
// this package's, so it is asserted here: if a future Go accepts bracket
// syntax around a name, this fails rather than the bypass quietly publishing
// a percent-encoded authority.
func TestBracketedHostsAreValidatedByTheParser(t *testing.T) {
	for _, raw := range []string{
		"https://[\u4f8b\u3048]/x",       // a name in brackets
		"https://[\u4f8b\u3048]:8443/x",  // ... with a port
		"https://[%E4%BE%8B%E3%81%88]/x", // ... written pre-escaped
		"https://[not-an-ip]/x",
		"https://[example.com]/x",
		"https://[v7.abc]/x", // an IPvFuture literal, which ParseAddr refuses
	} {
		if _, err := url.Parse(raw); err == nil {
			t.Errorf("url.Parse accepted %q; the bracketed-host bypass in hostToASCII is no longer safe", raw)
		}
		if got, ok := NormalizeURL(raw, URLFormReference); ok {
			t.Errorf("%q was published as %q", raw, got)
		}
	}
	// The literals the bypass exists for still parse and still publish.
	for _, raw := range []string{
		"https://[2001:db8::1]/x",
		"http://[fe80::1%25eth0]/x",
	} {
		if _, err := url.Parse(raw); err != nil {
			t.Errorf("url.Parse rejected the valid literal %q: %v", raw, err)
		}
		if _, ok := NormalizeURL(raw, URLFormReference); !ok {
			t.Errorf("%q was rejected", raw)
		}
	}
}

// TestCaseMappingIsTheLibrarysToDo pins that the conversion runs before the
// generic lowercasing, and why the order matters. strings.ToLower applies Go's
// simple case mapping, which is not the mapping IDNA specifies: it turns "İ"
// into "i" and drops the dot UTS #46 keeps. Lowercasing first therefore hands
// the library a different name than the one that arrived -- and since the
// result is plain ASCII it never reaches the library at all -- so a manifest
// naming one host published another.
func TestCaseMappingIsTheLibrarysToDo(t *testing.T) {
	for raw, want := range map[string]string{
		"https://İ.example/x":        "https://xn--i-9bb.example/x",
		"https://İSTANBUL.example/x": "https://xn--istanbul-o0e.example/x",
		// A case where the two mappings agree, so the fix is not just
		// "anything with an uppercase letter changed".
		"https://ẞ.example/x": "https://xn--zca.example/x",
		// ASCII still lowercases: the generic pass is what handles the hosts
		// that never reach the library.
		"https://EXAMPLE.com/X":   "https://example.com/X",
		"https://Example.COM/x":   "https://example.com/x",
		"https://[2001:DB8::1]/x": "https://[2001:db8::1]/x",
	} {
		got, ok := NormalizeURL(raw, URLFormReference)
		if !ok {
			t.Errorf("%q was rejected", raw)
			continue
		}
		if got != want {
			t.Errorf("%q = %q, want %q", raw, got, want)
		}
		// Whatever it published must survive a second pass unchanged: this
		// rule runs on write and again on read.
		if twice, ok := NormalizeURL(got, URLFormReference); !ok || twice != got {
			t.Errorf("re-normalizing %q gave %q (ok=%v)", got, twice, ok)
		}
	}
}

// TestUnicodeWhitespaceInAQueryIsRefused pins a defect the fuzzer found while
// this change was in review, present since the reference form was added. The
// query is the one part of a URL that url.URL writes back verbatim, and the
// guard against a raw space in it scanned bytes for "b <= ' '" -- the ASCII
// half of a rule the function's own TrimSpace applies over all of Unicode. A
// query ending in U+2000 therefore published on the first pass and normalized
// to something shorter on the second, so a stored value failed its own gate
// when read back.
func TestUnicodeWhitespaceInAQueryIsRefused(t *testing.T) {
	for _, raw := range []string{
		// The space has to sit where TrimSpace cannot reach it: between other
		// query bytes, or ahead of a fragment. A space at the very end of the
		// string is trimmed before parsing and never reaches the query, which
		// is why the input the fuzzer produced carries a trailing "#".
		"http://0?\u2000#",
		"https://e.com/a?b\u2000c",
		"https://e.com/a?b\u3000c", // an ideographic space
		"https://e.com/a?b\u00a0c", // a no-break space
		"https://e.com/a?b\u3000#f",
		"https://e.com/a?b\tc", // the ASCII half the old byte scan caught
	} {
		if got, ok := NormalizeURL(raw, URLFormReference); ok {
			t.Errorf("%q was published as %q", raw, got)
		}
	}
	// An escaped space is how a query says "space", and it still publishes.
	for _, raw := range []string{
		"https://e.com/a?b%20c",
		"https://e.com/a?b+c",
		"https://e.com/a?q=%E4%BE%8B",
	} {
		got, ok := NormalizeURL(raw, URLFormReference)
		if !ok {
			t.Errorf("%q was rejected", raw)
			continue
		}
		if twice, ok := NormalizeURL(got, URLFormReference); !ok || twice != got {
			t.Errorf("re-normalizing %q gave %q (ok=%v)", got, twice, ok)
		}
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

// TestTrailingSeparatorsOnUnicodeHostsAreRefused pins a deliberate asymmetry.
// A trailing separator marks an absolute name and is legal, but the label
// check reads it as an empty final label, so a Unicode name carrying one is
// refused -- while the ASCII spelling publishes untouched on the fast path,
// which applies no label validation at all.
//
// An earlier revision held the separator back so both spellings published.
// That is what the three review findings on this function were about, and it
// was removed rather than sharpened again; see hostToASCII. The asymmetry is
// between untouched legacy behavior and validated new behavior, not between
// two spellings of one rule.
//
// Two review rounds have now asserted the opposite -- that VerifyDNSLength
// permits a trailing root dot because the length arithmetic excludes it. Half
// of that is true: x/net does subtract the root label and its dot before
// measuring the name. But it rejects a trailing dot outright a few lines
// earlier, so ToASCII returns an error either way. Probed, not reasoned:
// hostLengths.ToASCII("example.com.") returns `idna: invalid label
// "example.com."`. The subtest at the end asserts that directly, so the next
// reading of that arithmetic has its answer already in the tree.
func TestTrailingSeparatorsOnUnicodeHostsAreRefused(t *testing.T) {
	for _, raw := range []string{
		"https://" + idnHost + "./docs",
		"https://" + idnHost + ".:8443/docs",
		"https://例え.テスト。/docs",
		"https://例え.テスト．/docs",
		"https://例え.テスト｡/docs",
	} {
		if got, ok := NormalizeURL(raw, URLFormReference); ok {
			t.Errorf("%q was published as %q; the root-marker hold-back is back", raw, got)
		}
	}
	// The ASCII spelling is untouched: it never reaches the label check.
	if got, ok := NormalizeURL("https://example.com./docs", URLFormReference); !ok || got != "https://example.com./docs" {
		t.Fatalf("got %q ok=%v, want the ASCII trailing dot untouched", got, ok)
	}
	// A name without the trailing separator is unaffected, so this refuses the
	// marker rather than the host.
	if got, ok := NormalizeURL("https://"+idnHost+"/docs", URLFormReference); !ok || got != "https://"+punyHost+"/docs" {
		t.Fatalf("got %q ok=%v, want the same host without a trailing separator to publish", got, ok)
	}
	// The library's own verdict, asserted directly rather than through
	// NormalizeURL, since it is the step under dispute.
	for _, name := range []string{"example.com.", "xn--r8jz45g.xn--zckzah."} {
		if _, err := hostLengths.ToASCII(name); err == nil {
			t.Errorf("hostLengths.ToASCII(%q) accepted a trailing root dot; the refusal above no longer follows from the library", name)
		}
	}
}

// TestUnicodeLabelSeparatorsAreTheLibrarysToKnow pins that a name written with
// a Unicode label separator publishes as the ASCII spelling it means. IDNA
// treats U+3002, U+FF0E and U+FF61 as separators and maps each to ".", so
// "例え。テスト" is "例え.テスト" -- and that mapping is the library's to know.
// A local table of those code points would be this package keeping its own
// copy of a Unicode property.
func TestUnicodeLabelSeparatorsAreTheLibrarysToKnow(t *testing.T) {
	for _, sep := range []string{"。", "．", "｡"} {
		raw := "https://例え" + sep + "テスト/docs"
		if got, ok := NormalizeURL(raw, URLFormReference); !ok || got != "https://"+punyHost+"/docs" {
			t.Errorf("separator %q: got %q ok=%v, want %q", sep, got, ok, "https://"+punyHost+"/docs")
		}
		// An interior empty label is refused however the separators are
		// written, so the mapping is not being read as "any dot is fine".
		empty := "https://例え" + sep + sep + "テスト/docs"
		if got, ok := NormalizeURL(empty, URLFormReference); ok {
			t.Errorf("doubled %q: published %q, which no resolver accepts", sep, got)
		}
	}
}

// TestScopedIPLiteralsSkipConversion pins that an IP literal is never handed
// to IDNA. A zone identifier can carry non-ASCII bytes -- url.Parse decodes
// "%25eth%C3%A9" into "%ethé" -- so such a literal misses the ASCII fast path
// and reaches the conversion, where reading the authority as "split at the
// last colon" truncated it to "[fe80:" and rejected an address net/url handles
// correctly.
func TestScopedIPLiteralsSkipConversion(t *testing.T) {
	for raw, want := range map[string]string{
		"http://[fe80::1%25ethé]/x":            "http://[fe80::1%25eth%C3%A9]/x",
		"http://[fe80::1%25ethé]:8443/x":       "http://[fe80::1%25eth%C3%A9]:8443/x",
		"http://[fe80::1%25ethé]:80/x":         "http://[fe80::1%25eth%C3%A9]/x",
		"http://[fe80::1%25eth0]/x":            "http://[fe80::1%25eth0]/x",
		"https://[2001:db8::1]:8443/pkg.tgz":   "https://[2001:db8::1]:8443/pkg.tgz",
		"https://[2001:db8::1]/a/pkg-1.0.0.tz": "https://[2001:db8::1]/a/pkg-1.0.0.tz",
	} {
		got, ok := NormalizeURL(raw, URLFormReference)
		if !ok {
			t.Errorf("%q was rejected", raw)
			continue
		}
		if got != want {
			t.Errorf("%q = %q, want %q", raw, got, want)
		}
	}
}

// TestTheValidationPassOnlyJudges pins the contract hostToASCII relies on: the
// second IDNA pass runs on a value the first already mapped, so it returns
// that value unchanged and only its error matters. If that stopped holding,
// the published host would be the un-revalidated one.
func TestTheValidationPassOnlyJudges(t *testing.T) {
	names := []string{
		idnHost, punyHost, "例え。テスト",
		"example.com", "a-b.example", "EXAMPLE.com",
	}
	checked := 0
	for _, name := range names {
		mapped, err := idna.Lookup.ToASCII(name)
		if err != nil {
			continue
		}
		got, err := hostLengths.ToASCII(mapped)
		if err != nil {
			continue
		}
		checked++
		if got != mapped {
			t.Errorf("the validation pass rewrote %q to %q", mapped, got)
		}
	}
	// Both passes reject on their own terms, so a case that never reaches the
	// comparison asserts nothing. Fail rather than pass vacuously.
	if checked != len(names) {
		t.Fatalf("only %d of %d names reached the comparison", checked, len(names))
	}
}
