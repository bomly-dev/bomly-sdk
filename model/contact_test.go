package model

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode"
)

func TestParseSPDXContact(t *testing.T) {
	for _, tc := range []struct {
		input    string
		wantKind ContactKind
		wantName string
		wantOK   bool
	}{
		{"Organization: Acme Inc", ContactKindOrganization, "Acme Inc", true},
		{"Person: Jane Doe", ContactKindPerson, "Jane Doe", true},
		{"NOASSERTION", ContactKindNoAssertion, "", true},
		{"noassertion", ContactKindNoAssertion, "", true},
		{"organization: Acme Inc", ContactKindOrganization, "Acme Inc", true},
		// The email parenthetical is stripped; see Contact's documentation.
		{"Organization: Acme Inc (info@acme.com)", ContactKindOrganization, "Acme Inc", true},
		{"Person: Jane Doe (jane@example.com)", ContactKindPerson, "Jane Doe", true},
		// SPDX requires a kind prefix. Guessing one would publish a claim the
		// document did not make.
		{"Acme Inc", ContactKindUnknown, "", false},
		{"", ContactKindUnknown, "", false},
		{"Organization:", ContactKindUnknown, "", false},
		{"Organization: (only@email.com)", ContactKindUnknown, "", false},
	} {
		got, ok := ParseSPDXContact(tc.input)
		if ok != tc.wantOK {
			t.Fatalf("ParseSPDXContact(%q) ok = %v, want %v (got %+v)", tc.input, ok, tc.wantOK, got)
		}
		if !ok {
			continue
		}
		if got.Kind != tc.wantKind || got.Name != tc.wantName {
			t.Fatalf("ParseSPDXContact(%q) = %+v, want kind %q name %q", tc.input, got, tc.wantKind, tc.wantName)
		}
	}
}

// TestContactCarriesNoEmailAddress pins the privacy decision: ADR-0037 defers
// supplier-contact privacy, so an address in an ingested document must not be
// retained anywhere on the value -- not in the name, not in a spare field.
func TestContactCarriesNoEmailAddress(t *testing.T) {
	contact, ok := ParseSPDXContact("Organization: Acme Inc (secrets@acme.com)")
	if !ok {
		t.Fatal("ParseSPDXContact rejected a valid supplier")
	}
	encoded, err := json.Marshal(contact)
	if err != nil {
		t.Fatalf("encode contact: %v", err)
	}
	if strings.Contains(string(encoded), "@") {
		t.Fatalf("encoded contact %s retains an email address", encoded)
	}
}

func TestContactSPDXRoundTrip(t *testing.T) {
	for _, input := range []string{"Organization: Acme Inc", "Person: Jane Doe", "NOASSERTION"} {
		contact, ok := ParseSPDXContact(input)
		if !ok {
			t.Fatalf("ParseSPDXContact(%q) rejected a valid value", input)
		}
		if got := contact.SPDXString(); got != input {
			t.Fatalf("round trip of %q produced %q", input, got)
		}
	}
	// A contact of unknown kind has no valid SPDX rendering.
	unknown := Contact{Name: "Acme Inc"}
	if got := unknown.SPDXString(); got != "" {
		t.Fatalf("unknown-kind contact rendered as %q, want the empty omit signal", got)
	}
}

func TestContactNormalizedGates(t *testing.T) {
	// A control character would corrupt SPDX's line-oriented tag form.
	if _, ok := (Contact{Kind: ContactKindOrganization, Name: "Acme\nInc"}).Normalized(); ok {
		t.Fatal("a name carrying a newline was accepted")
	}
	// URLs are held to the reference form: credentials are rejected, a bare
	// host is fine.
	withCreds := Contact{Kind: ContactKindOrganization, Name: "Acme", URL: "https://user:pw@acme.test/"}
	normalized, ok := withCreds.Normalized()
	if !ok {
		t.Fatal("a valid contact was rejected for its URL")
	}
	if normalized.URL != "" {
		t.Fatalf("credentials survived normalization: %q", normalized.URL)
	}
	bareHost := Contact{Kind: ContactKindOrganization, Name: "Acme", URL: "https://acme.test"}
	if normalized, ok = bareHost.Normalized(); !ok || normalized.URL == "" {
		t.Fatalf("a bare-host URL was dropped: %+v ok=%v", normalized, ok)
	}
}

// TestContainsControlChar pins the single-line gate to the Unicode Cc
// category: C0, DEL, and the C1 range. C1 is the case that was missed --
// U+009B is the one-character control sequence introducer, which a terminal
// printing the value can act on exactly as it would on ESC [.
func TestContainsControlChar(t *testing.T) {
	for _, value := range []string{
		"with\x00nul", "with\ttab", "with\nnewline", "with\x1bescape", "with\x7fdelete",
		"with\u0080pad", "with\u0085next-line", "with\u009bcsi", "with\u009fapc",
		"\u009b", "trailing\u009b",
	} {
		if !ContainsControlChar(value) {
			t.Errorf("ContainsControlChar(%q) = false, want true", value)
		}
	}
	// Not controls: printable Latin-1 on either side of the C1 range, the
	// no-break space that follows it, and format characters (Cf), which are
	// a different category and not what this gate is about.
	for _, value := range []string{
		"", "Acme Inc", "~", "Caf\u00e9", "no\u00a0break", "\u00ff", "zero\u200bwidth", "\u4e2d\u6587",
	} {
		if ContainsControlChar(value) {
			t.Errorf("ContainsControlChar(%q) = true, want false", value)
		}
	}
	// Every rune the standard library calls a control, and only those.
	for r := rune(0); r <= 0x10ffff; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			continue // surrogates do not survive string conversion
		}
		if got, want := ContainsControlChar(string(r)), unicode.IsControl(r); got != want {
			t.Fatalf("ContainsControlChar(%U) = %v, want unicode.IsControl's %v", r, got, want)
		}
	}
}

// TestContactNameRefusesC1Controls pins the contact gate on the C1 case: a
// supplier name read from a third-party document that carries U+009B is not
// published.
func TestContactNameRefusesC1Controls(t *testing.T) {
	if _, ok := (Contact{Kind: ContactKindOrganization, Name: "Acme\u009b31mInc"}).Normalized(); ok {
		t.Fatal("a name carrying U+009B was accepted")
	}
	if contact, ok := ParseSPDXContact("Organization: Acme\u0085Inc"); ok {
		t.Fatalf("an SPDX supplier carrying U+0085 parsed as %+v", contact)
	}
	if got, ok := (Contact{Kind: ContactKindOrganization, Name: "Caf\u00e9 Inc"}).Normalized(); !ok || got.Name != "Caf\u00e9 Inc" {
		t.Fatalf("a Latin-1 name was refused: %+v ok=%v", got, ok)
	}
}

// TestContactDropsAddressesWhereverTheyAppear pins the privacy rule against
// the sloppy-document case the fuzzer found: a producer that writes the
// address as the name rather than in SPDX's parenthetical must not get it
// stored. Stripping only the parenthetical would honor the decision for
// well-formed input and break it for everything else.
func TestContactDropsAddressesWhereverTheyAppear(t *testing.T) {
	// A name that is nothing but an address leaves no usable name.
	if contact, ok := ParseSPDXContact("Person: jane@example.com"); ok {
		t.Fatalf("a bare address was accepted as a name: %+v", contact)
	}
	// A name carrying an address keeps the name and drops the address.
	contact, ok := ParseSPDXContact("Person: Jane Doe jane@example.com")
	if !ok {
		t.Fatal("a contact with a real name was rejected")
	}
	if contact.Name != "Jane Doe" {
		t.Fatalf("name = %q, want the address-shaped token dropped", contact.Name)
	}
	// The rule is on the value, not on the parser: a hand-built contact is
	// held to it too.
	built, ok := (Contact{Kind: ContactKindOrganization, Name: "Acme ops@acme.test"}).Normalized()
	if !ok || built.Name != "Acme" {
		t.Fatalf("hand-built contact normalized to %+v, want the address dropped", built)
	}
}

// TestContactPreservesNonEmailParentheticals pins a round-trip break the
// fuzzer caught: stripping every trailing "(...)" group meant a name that
// legitimately ends in one lost it on the *second* read, so a contact exported
// and re-ingested did not survive its own round trip.
func TestContactPreservesNonEmailParentheticals(t *testing.T) {
	contact, ok := ParseSPDXContact("Organization: Acme Inc (Europe)")
	if !ok {
		t.Fatal("a valid supplier was rejected")
	}
	if contact.Name != "Acme Inc (Europe)" {
		t.Fatalf("name = %q, want the qualifier preserved", contact.Name)
	}
	// Exporting and re-reading reaches the same value.
	again, ok := ParseSPDXContact(contact.SPDXString())
	if !ok || again != contact {
		t.Fatalf("round trip gave %+v (ok=%v), want %+v", again, ok, contact)
	}
	// An address parenthetical is still stripped.
	withEmail, ok := ParseSPDXContact("Organization: Acme Inc (info@acme.com)")
	if !ok || withEmail.Name != "Acme Inc" {
		t.Fatalf("name = %+v, want the address parenthetical removed", withEmail)
	}
}

// TestContactURLCarriesNoAddress pins the privacy rule against the one place
// an address could still reach a stored contact: NormalizeURL rejects an
// address in the userinfo position, but the reference form keeps the path,
// query, and fragment.
func TestContactURLCarriesNoAddress(t *testing.T) {
	for _, raw := range []string{
		"https://acme.test/contact?email=jane@example.com",
		"https://acme.test/contact?email=jane%40example.com",
		"https://acme.test/#write-to-jane@example.com",
		// Addresses are internationalized. An ASCII-only check would enforce
		// the no-email contract for English-speaking users and publish
		// everyone else's personal data.
		"https://acme.test/?email=josé@bücher.example",
		"https://acme.test/?email=Жан@почта.рф",
		"https://acme.test/?email=%D0%96%D0%B0%D0%BD@почта.рф",
	} {
		contact, ok := (Contact{Kind: ContactKindOrganization, Name: "Acme", URL: raw}).Normalized()
		if !ok {
			t.Fatalf("contact with URL %q was rejected outright; the name should survive", raw)
		}
		if contact.URL != "" {
			t.Fatalf("URL %q kept an address: %q", raw, contact.URL)
		}
	}
	// The rule must not catch the shapes that merely contain "@": an npm
	// scope path and a coordinate are both common and neither is an address.
	for _, raw := range []string{
		"https://npmjs.test/package/@scope/pkg",
		"https://acme.test/releases/pkg@1.0.0",
		"https://acme.test/",
	} {
		contact, ok := (Contact{Kind: ContactKindOrganization, Name: "Acme", URL: raw}).Normalized()
		if !ok || contact.URL != raw {
			t.Fatalf("URL %q was dropped as an address: %+v (ok=%v)", raw, contact, ok)
		}
	}
}

// TestContactURLRejectsAddressLiterals pins the second domain form the address
// grammar allows. A bracketed literal has no dotted alphabetic suffix, so a
// name-only pattern published "jane@[192.0.2.1]" intact.
func TestContactURLRejectsAddressLiterals(t *testing.T) {
	for _, raw := range []string{
		"https://acme.test/?email=jane@[192.0.2.1]",
		"https://acme.test/?email=jane@[IPv6:2001:db8::1]",
		"https://acme.test/?email=jane%40%5B192.0.2.1%5D",
	} {
		contact, ok := (Contact{Kind: ContactKindOrganization, Name: "Acme", URL: raw}).Normalized()
		if !ok {
			t.Fatalf("contact with URL %q was rejected outright; the name should survive", raw)
		}
		if contact.URL != "" {
			t.Fatalf("URL %q kept an address literal: %q", raw, contact.URL)
		}
	}
	// The bracket form must not swallow unrelated URLs.
	for _, raw := range []string{"https://acme.test/docs%5Bv2%5D", "https://npmjs.test/package/@scope/pkg"} {
		contact, ok := (Contact{Kind: ContactKindOrganization, Name: "Acme", URL: raw}).Normalized()
		if !ok || contact.URL == "" {
			t.Fatalf("URL %q was dropped as an address: %+v", raw, contact)
		}
	}
}

// TestParseContactKindBoundsItsInput pins the bound, and that it sits well
// above every real spelling.
func TestParseContactKindBoundsItsInput(t *testing.T) {
	oversized := strings.Repeat("x", maxContactKindLength+1)
	_, err := ParseContactKind(oversized)
	if err == nil {
		t.Fatal("an over-long contact kind was accepted")
	}
	// The error must come from the bound, not from the vocabulary lookup that
	// would reject it anyway — and it must not quote the whole input back.
	if !strings.Contains(err.Error(), "over the") {
		t.Fatalf("error = %v, want the length bound to have rejected it", err)
	}
	if len(err.Error()) > 200 {
		t.Fatalf("error message is %d bytes; it echoes the rejected input", len(err.Error()))
	}
	for _, kind := range []ContactKind{ContactKindOrganization, ContactKindPerson, ContactKindNoAssertion} {
		if len(kind) > maxContactKindLength {
			t.Fatalf("declared kind %q is over the parse limit", kind)
		}
	}
}

// TestParseSPDXContactBoundsItsInput pins that the parser's work is bounded
// before it walks the value. The name limit only applies after trimming,
// prefix matching, parenthetical stripping, and address-token removal have
// each scanned the whole input.
func TestParseSPDXContactBoundsItsInput(t *testing.T) {
	oversized := "Organization: " + strings.Repeat("x", maxSPDXContactLength)
	if _, ok := ParseSPDXContact(oversized); ok {
		t.Fatal("an oversized supplier string was accepted")
	}
	// The case the name limit alone does not catch: a short name behind a
	// huge parenthetical. The parenthetical is stripped before the name is
	// measured, so without a bound on the whole value this parses
	// successfully after walking every byte of it.
	hugeParenthetical := "Organization: Acme (" + strings.Repeat("x", maxSPDXContactLength) + "someone@example.com)"
	if contact, ok := ParseSPDXContact(hugeParenthetical); ok {
		t.Fatalf("a supplier with a %d byte parenthetical was accepted as %+v", len(hugeParenthetical), contact)
	}
	// A realistic supplier with an email parenthetical still parses: the
	// bound must sit above the name limit, not at it.
	long := "Organization: " + strings.Repeat("a", maxContactNameLength-1) + " (someone@example.com)"
	if len(long) > maxSPDXContactLength {
		t.Fatalf("fixture is %d bytes, over the parse bound; the bound is too tight", len(long))
	}
	contact, ok := ParseSPDXContact(long)
	if !ok || contact.Name == "" {
		t.Fatalf("a realistic long supplier was rejected: %+v", contact)
	}
}

// TestReferenceURLRejectsUndecodableQuery pins a privacy hole a malformed
// escape opened. url.URL writes RawQuery back verbatim, so a truncated escape
// survived normalization — and every consumer that tried to decode the query,
// including the contact gate looking for an email address, got a decode error
// and concluded the value was clean. An encoded address published on exactly
// that reasoning.
func TestReferenceURLRejectsUndecodableQuery(t *testing.T) {
	hidden := "https://acme.test/?email=jane%40example.com%"
	if got, ok := NormalizeURL(hidden, URLFormReference); ok {
		t.Fatalf("a URL with an undecodable query was accepted: %q", got)
	}
	contact, ok := (Contact{Kind: ContactKindOrganization, Name: "Acme", URL: hidden}).Normalized()
	if !ok {
		t.Fatal("the contact should survive; only its URL is unpublishable")
	}
	if contact.URL != "" {
		t.Fatalf("an encoded address published behind a malformed escape: %q", contact.URL)
	}
	// A well-formed escaped query is still kept.
	fine := "https://acme.test/?q=a%20b"
	if got, ok := NormalizeURL(fine, URLFormReference); !ok || got != fine {
		t.Fatalf("NormalizeURL(%q) = %q ok=%v, want it kept", fine, got, ok)
	}
}

// A description that survives one pass must survive the next unchanged.
// Repairing invalid UTF-8 turns each bad byte into a three-byte U+FFFD, so a
// value under the bound came out at three times the maximum, and the second
// pass -- seeing an over-long value -- returned "". Export, ingest, export
// lost the description on the second hop. Found by a fuzz target in
// bomly-cli.
func TestNormalizeDescriptionIsAFixedPointWithinItsBound(t *testing.T) {
	// The reproducer from the report: 3006 bytes in, 9006 out, then 0.
	amplified := "00" + strings.Repeat("\xff", 3000) + "0000"
	once := NormalizeDescription(amplified)
	if once != "" {
		t.Fatalf("a value that repairs to %d bytes, past the %d bound, was kept", len(once), maxDescriptionLength)
	}

	// Repair that stays within the bound is kept, and is stable.
	small := "a\xffb"
	if got := NormalizeDescription(small); got != "a\uFFFDb" || NormalizeDescription(got) != got {
		t.Fatalf("NormalizeDescription(%q) = %q, then %q; want a stable repaired value", small, got, NormalizeDescription(got))
	}
	// Right at the edge: the largest repair that fits within the bound
	// survives (three bytes per replaced byte, so it lands just under a
	// bound that is not a multiple of three), and one more replaced byte
	// does not.
	atBound := strings.Repeat("\xff", maxDescriptionLength/3)
	if got := NormalizeDescription(atBound); len(got) != 3*(maxDescriptionLength/3) || NormalizeDescription(got) != got {
		t.Fatalf("repair landing within the bound: len=%d, stable=%v; want kept and stable", len(got), NormalizeDescription(got) == got)
	}
	if got := NormalizeDescription(atBound + "\xff"); got != "" {
		t.Fatalf("repair one U+FFFD past the bound was kept at %d bytes", len(got))
	}

	for _, value := range []string{
		"  A tidy package.  ", "line one\nline two", "clean\x00text\x07",
		strings.Repeat("a", maxDescriptionLength), strings.Repeat("a", maxDescriptionLength+1), amplified, small,
	} {
		once := NormalizeDescription(value)
		if twice := NormalizeDescription(once); twice != once {
			t.Errorf("NormalizeDescription(%q...) = %d bytes, then %d bytes; want a fixed point", value[:min(len(value), 12)], len(once), len(twice))
		}
		if len(once) > maxDescriptionLength {
			t.Errorf("NormalizeDescription returned %d bytes, past the %d bound", len(once), maxDescriptionLength)
		}
	}
}

func TestNormalizeDescription(t *testing.T) {
	if got := NormalizeDescription("  A tidy package.  "); got != "A tidy package." {
		t.Fatalf("NormalizeDescription trimmed to %q", got)
	}
	// Line structure is part of a legitimate description.
	if got := NormalizeDescription("line one\nline two\ttabbed"); got != "line one\nline two\ttabbed" {
		t.Fatalf("NormalizeDescription damaged line structure: %q", got)
	}
	// Other control characters came from a malformed document.
	if got := NormalizeDescription("clean\x00text\x07"); got != "cleantext" {
		t.Fatalf("NormalizeDescription = %q, want the control characters dropped", got)
	}
	// Over-long input yields nothing rather than a truncation presented as a
	// complete description.
	if got := NormalizeDescription(strings.Repeat("a", maxDescriptionLength+1)); got != "" {
		t.Fatalf("an over-long description survived as %d bytes", len(got))
	}
}

func TestNormalizeHomepageUsesTheReferenceForm(t *testing.T) {
	if got := NormalizeHomepage("https://example.test"); got != "https://example.test" {
		t.Fatalf("NormalizeHomepage rejected a bare-host project page: %q", got)
	}
	if got := NormalizeHomepage("https://user:pw@example.test/"); got != "" {
		t.Fatalf("NormalizeHomepage published credentials: %q", got)
	}
	if got := NormalizeHomepage("/opt/local/project"); got != "" {
		t.Fatalf("NormalizeHomepage published a local path: %q", got)
	}
}
