package sdk

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ContactKind says what sort of party a Contact names. SPDX writes the kind
// inline ("Organization: Acme Inc"), and CycloneDX implies it by which field
// carries the value, so the SDK stores it explicitly and each codec projects
// it.
type ContactKind string

const (
	// ContactKindUnknown means the source named a party without saying
	// whether it is a person or an organization.
	ContactKindUnknown ContactKind = ""
	// ContactKindOrganization names a company, foundation, or team.
	ContactKindOrganization ContactKind = "organization"
	// ContactKindPerson names an individual.
	ContactKindPerson ContactKind = "person"
	// ContactKindNoAssertion is SPDX's explicit "the document declines to
	// say". It is not the same as an absent contact: one is a statement that
	// the information was withheld, the other is silence, and SPDX
	// round-trips the difference.
	ContactKindNoAssertion ContactKind = "noassertion"
)

// ParseContactKind normalizes a contact kind. An empty value is unknown, which
// is legal; anything else unrecognized is an error.
func ParseContactKind(value string) (ContactKind, error) {
	switch ContactKind(strings.ToLower(strings.TrimSpace(value))) {
	case "":
		return ContactKindUnknown, nil
	case ContactKindOrganization:
		return ContactKindOrganization, nil
	case ContactKindPerson:
		return ContactKindPerson, nil
	case ContactKindNoAssertion:
		return ContactKindNoAssertion, nil
	default:
		return ContactKindUnknown, fmt.Errorf("unsupported contact kind %q", value)
	}
}

// Contact names a party a document makes a claim about: who supplied a package
// (SPDX PackageSupplier, CycloneDX supplier) or who originally authored it
// (SPDX PackageOriginator, CycloneDX author/publisher).
//
// # No email address
//
// A contact deliberately carries no email address, though both formats have a
// slot for one. ADR-0037 defers supplier-contact privacy to its own review,
// and an email is personal data that would flow from an ingested document into
// Bomly's JSON output, its logs, and every re-export. Storing it now and
// deciding later is not neutral -- the exposure happens at storage, not at
// emission -- so the field does not exist yet.
//
// The consequence is stated rather than hidden: an SPDX supplier written as
// "Organization: Acme Inc (info@acme.com)" round-trips as "Organization: Acme
// Inc". The name survives, the address does not. When the privacy review
// lands, an email field is an additive change here.
type Contact struct {
	// Kind says whether the party is an organization or a person, or that
	// the document explicitly declined to say.
	Kind ContactKind `json:"kind,omitempty"`
	// Name is the party's name as the source stated it, minus any email
	// parenthetical.
	Name string `json:"name,omitempty"`
	// URL is the party's own URL, when the source carried one. CycloneDX's
	// organizational entity has a url list; SPDX has no slot for it.
	URL string `json:"url,omitempty"`
}

// maxContactNameLength bounds a party name. Real supplier names run to a few
// dozen characters; the allowance covers long legal names without admitting a
// value that is really a document.
const maxContactNameLength = 256

// spdxNoAssertion is SPDX's explicit withheld-value token.
const spdxNoAssertion = "NOASSERTION"

// Empty reports whether the contact says nothing.
func (c Contact) Empty() bool {
	return c.Kind == ContactKindUnknown && strings.TrimSpace(c.Name) == "" && strings.TrimSpace(c.URL) == ""
}

// Normalized returns the contact with its claim re-checked, or false when it
// says nothing publishable. It is the gate for a contact that arrived from a
// plugin, an ingested document, or a hand-built value.
func (c Contact) Normalized() (Contact, bool) {
	normalized := Contact{Name: strings.TrimSpace(c.Name)}
	if kind, err := ParseContactKind(string(c.Kind)); err == nil {
		normalized.Kind = kind
	}
	// A name is written verbatim into a document field, so a value carrying a
	// newline or a control character would corrupt the line-oriented SPDX tag
	// form outright and is not a name in any case.
	if len(normalized.Name) > maxContactNameLength || containsControlChar(normalized.Name) {
		normalized.Name = ""
	}
	normalized.Name = stripAddressTokens(normalized.Name)
	if url, ok := NormalizeURL(c.URL, URLFormReference); ok {
		normalized.URL = url
	}
	// NOASSERTION is a claim in its own right and needs no name; every other
	// kind is only meaningful with one.
	if normalized.Kind == ContactKindNoAssertion {
		normalized.Name = ""
		normalized.URL = ""
		return normalized, true
	}
	if normalized.Name == "" {
		return Contact{}, false
	}
	return normalized, true
}

// maxDescriptionLength bounds a carried component description. Registry
// summaries run to a paragraph; the allowance covers a long README abstract
// without letting an ingested document carry a manual per component.
const maxDescriptionLength = 8 * 1024

// NormalizeDescription is the gate for a component description. Descriptions
// arrive from untrusted registry records and SBOM documents and are rendered
// into terminals and written into published documents, so the value is
// trimmed, bounded, and stripped of control characters that would corrupt the
// output. Line breaks and tabs survive: both formats carry multi-line
// descriptions, and removing them would damage a legitimate value.
//
// Over-long input yields "" rather than a truncation, because half a
// description attributed to a package is a false assertion where no
// description is merely a missing one.
func NormalizeDescription(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || len(trimmed) > maxDescriptionLength {
		return ""
	}
	var b strings.Builder
	b.Grow(len(trimmed))
	for _, r := range trimmed {
		switch {
		case r == '\n', r == '\r', r == '\t':
			b.WriteRune(r)
		case r < ' ' || r == 0x7f:
			// Dropped: a control character here came from a malformed
			// document, never from a description someone wrote.
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// NormalizeHomepage is the gate for a component homepage: URLFormReference,
// which keeps a bare host and a query -- both normal for a project page --
// while rejecting credentials, local paths, and non-http schemes. It returns
// "" when the value cannot be published.
func NormalizeHomepage(value string) string {
	normalized, ok := NormalizeURL(value, URLFormReference)
	if !ok {
		return ""
	}
	return normalized
}

// containsControlChar reports whether value carries a C0 control character or
// DEL. Used by fields that are written verbatim into a published document.
func containsControlChar(value string) bool {
	for _, r := range value {
		if r < ' ' || r == 0x7f {
			return true
		}
	}
	return false
}

// SPDXString renders the contact in SPDX's PackageSupplier/PackageOriginator
// form, or "" when the contact has no SPDX projection. SPDX requires the kind
// prefix, so a contact of unknown kind has no valid rendering -- "" means omit
// the field rather than emit something that will not validate.
func (c Contact) SPDXString() string {
	normalized, ok := c.Normalized()
	if !ok {
		return ""
	}
	switch normalized.Kind {
	case ContactKindNoAssertion:
		return spdxNoAssertion
	case ContactKindOrganization:
		return "Organization: " + normalized.Name
	case ContactKindPerson:
		return "Person: " + normalized.Name
	default:
		return ""
	}
}

// ParseSPDXContact reads SPDX's PackageSupplier/PackageOriginator form. It
// accepts "Organization: <name>", "Person: <name>", and "NOASSERTION", and
// strips the optional "(<email>)" suffix the format allows -- see the type's
// documentation for why the address is not retained. It returns false when the
// value carries no publishable claim.
func ParseSPDXContact(value string) (Contact, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return Contact{}, false
	}
	if strings.EqualFold(trimmed, spdxNoAssertion) {
		return Contact{Kind: ContactKindNoAssertion}, true
	}
	kind := ContactKindUnknown
	switch {
	case hasCaseInsensitivePrefix(trimmed, "Organization:"):
		kind = ContactKindOrganization
		trimmed = trimmed[len("Organization:"):]
	case hasCaseInsensitivePrefix(trimmed, "Person:"):
		kind = ContactKindPerson
		trimmed = trimmed[len("Person:"):]
	default:
		// SPDX requires one of the two prefixes. A bare name is not a valid
		// supplier value, and guessing a kind would publish an assertion the
		// document did not make.
		return Contact{}, false
	}
	name := strings.TrimSpace(stripEmailParenthetical(trimmed))
	return Contact{Kind: kind, Name: name}.Normalized()
}

// hasCaseInsensitivePrefix reports whether value begins with prefix, ignoring
// case.
func hasCaseInsensitivePrefix(value, prefix string) bool {
	return len(value) >= len(prefix) && strings.EqualFold(value[:len(prefix)], prefix)
}

// stripAddressTokens removes any whitespace-delimited token containing "@".
//
// The parenthetical is where SPDX puts an email address, but nothing forces a
// producer to use it: a document that writes "Person: jane@example.com" states
// the address as the name. Stripping only the parenthetical would honor the
// no-email decision for well-formed documents and quietly break it for sloppy
// ones, which is the wrong way round -- a privacy rule that holds only when
// the input is tidy is not a rule. So the check is on the value, not on where
// it sat: a name is what remains after every address-shaped token is removed,
// and a "name" that was nothing but an address leaves the contact with no
// usable name, which Normalized then rejects.
//
// The rule deliberately catches any "@", not just a strict address grammar. A
// party name containing one is vanishingly rare, and the cost of dropping such
// a name is a missing supplier, while the cost of keeping an address is
// publishing personal data the review has not yet cleared.
func stripAddressTokens(value string) string {
	if !strings.Contains(value, "@") {
		return value
	}
	kept := make([]string, 0, 4)
	for _, field := range strings.Fields(value) {
		if strings.Contains(field, "@") {
			continue
		}
		kept = append(kept, field)
	}
	return strings.Join(kept, " ")
}

// stripEmailParenthetical removes a trailing "(...)" group, which is where
// SPDX puts the optional email address.
func stripEmailParenthetical(value string) string {
	trimmed := strings.TrimSpace(value)
	if !strings.HasSuffix(trimmed, ")") {
		return trimmed
	}
	open := strings.LastIndex(trimmed, "(")
	if open < 0 {
		return trimmed
	}
	return strings.TrimSpace(trimmed[:open])
}

// Clone returns a deep copy of the contact.
func (c *Contact) Clone() *Contact {
	if c == nil {
		return nil
	}
	return new(*c)
}

// contactWire carries Contact's fields without its methods, so the JSON hooks
// below can encode and decode without recursing.
type contactWire Contact

// UnmarshalJSON applies the contact rule as a value arrives, so a party that
// would be rejected on read cannot be stored, forwarded, or written back out.
// A contact that says nothing publishable decodes to the zero value,
// following DependencyOrigin.
func (c *Contact) UnmarshalJSON(data []byte) error {
	var wire contactWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	normalized, ok := Contact(wire).Normalized()
	if !ok {
		*c = Contact{}
		return nil
	}
	*c = normalized
	return nil
}

// MarshalJSON applies the same rule on the way out.
func (c Contact) MarshalJSON() ([]byte, error) {
	normalized, ok := c.Normalized()
	if !ok {
		return json.Marshal(contactWire{})
	}
	return json.Marshal(contactWire(normalized))
}
