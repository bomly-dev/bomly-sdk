package purlkit

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/anchore/packageurl-go"
)

// ErrInvalidPURL reports a package URL that cannot be built or parsed. Every
// failure from Parse, Build, and their derivatives matches it with errors.Is,
// including failures surfaced by the underlying parser.
var ErrInvalidPURL = errors.New("invalid package URL")

// maxInputSize bounds untrusted input before parsing (the repository's fuzz
// convention, enforced in production here because package URLs arrive from
// untrusted SBOMs and registry responses and Parse re-parses while
// canonicalizing).
const maxInputSize = 1 << 20

// Qualifier is one key/value qualifier of a package URL. Keys are lowercase
// in canonical form; qualifier lists are sorted by key.
type Qualifier struct {
	Key   string
	Value string
}

// PURL is the structured form of a package URL. Unlike the legacy root
// builder it carries qualifiers and subpath, so identities such as
// pkg:maven/g/a@1?type=jar and pkg:golang/m@v1#sub are representable.
type PURL struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers []Qualifier
	Subpath    string
}

// Parse parses and validates an untrusted package URL string. The returned
// value is canonical: qualifier keys are lowercased and sorted,
// type-specific case rules are applied, and rendering it with String and
// parsing it again yields the same value. Parse never panics.
func Parse(value string) (PURL, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return PURL{}, ErrInvalidPURL
	}
	out, _, err := stabilize(value)
	return out, err
}

// stabilize iterates parse-and-render until the rendering stops changing.
// The underlying library is not idempotent on every input: rendering can
// expose percent-encoded bytes that the next parse decodes differently
// (e.g. an encoded leading space in a namespace segment). A canonical form
// must be stable, so input that will not stabilize within a few rounds is
// rejected rather than given an unstable identity. Both entry points share
// this core: Parse feeds it raw strings, Build feeds it its own rendering.
func stabilize(value string) (PURL, string, error) {
	const maxCanonicalizationRounds = 4
	for range maxCanonicalizationRounds {
		// The bound lives here so Parse and Build enforce it identically: a
		// Build whose rendered form exceeds it must fail now, not return an
		// output the public Parse would later reject — that would break the
		// documented fixed-point property and allow repeated parsing of
		// arbitrarily large structured input.
		if len(value) > maxInputSize {
			return PURL{}, "", ErrInvalidPURL
		}
		parsed, err := packageurl.FromString(value)
		if err != nil {
			return PURL{}, "", fmt.Errorf("%w: %v", ErrInvalidPURL, err)
		}
		restoreNPMScope(&parsed)
		if err := parsed.Normalize(); err != nil {
			return PURL{}, "", fmt.Errorf("%w: %v", ErrInvalidPURL, err)
		}
		out := fromPackageURL(parsed)
		rendered, err := renderOnce(out)
		if err != nil {
			return PURL{}, "", err
		}
		if rendered == value {
			return out, rendered, nil
		}
		value = rendered
	}
	return PURL{}, "", ErrInvalidPURL
}

// String renders the canonical string form, or "" when the value does not
// normalize. Use Build when the failure reason matters.
func (p PURL) String() string {
	rendered, err := Build(p)
	if err != nil {
		return ""
	}
	return rendered
}

// Build normalizes the parts and renders the canonical string form. Type and
// name are required; qualifiers and subpath are preserved, which the legacy
// root builder cannot do. The output is a Parse fixed point: structured
// parts can carry the same renderer-unstable bytes as raw strings, so the
// single-pass rendering is stabilized before it is returned, and parts that
// will not stabilize are rejected rather than given an unstable identity.
func Build(p PURL) (string, error) {
	rendered, err := renderOnce(p)
	if err != nil {
		return "", err
	}
	_, stable, err := stabilize(rendered)
	if err != nil {
		return "", err
	}
	return stable, nil
}

// renderOnce validates the parts and performs a single normalize-and-render
// pass — the non-idempotent primitive that stabilize iterates.
func renderOnce(p PURL) (string, error) {
	purlType := strings.TrimSpace(strings.ToLower(p.Type))
	name := strings.TrimSpace(p.Name)
	if purlType == "" || name == "" {
		return "", ErrInvalidPURL
	}
	for _, qualifier := range p.Qualifiers {
		// A blank key is malformed input, not an absent qualifier; dropping
		// it silently would let untrusted data bypass the validation
		// boundary while looking identical to a qualifier-free package.
		if strings.TrimSpace(qualifier.Key) == "" {
			return "", fmt.Errorf("%w: qualifier with blank key", ErrInvalidPURL)
		}
	}
	built := packageurl.NewPackageURL(purlType, strings.TrimSpace(p.Namespace), name,
		strings.TrimSpace(p.Version), toLibQualifiers(p.Qualifiers), strings.TrimSpace(p.Subpath))
	if built == nil {
		return "", ErrInvalidPURL
	}
	restoreNPMScope(built)
	if err := built.Normalize(); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidPURL, err)
	}
	return built.ToString(), nil
}

// Canonicalize normalizes a package URL string, returning "" when the value
// does not parse. Signature-compatible with the root CanonicalizePackageURL.
func Canonicalize(value string) string {
	parsed, err := Parse(value)
	if err != nil {
		return ""
	}
	return parsed.String()
}

// Base strips version, qualifiers, and subpath, keeping the package identity
// (type, namespace, name). It works structurally on the parsed form —
// replacing the legacy string surgery that cut at the first '?' and the last
// '@', which mishandled subpath-carrying and version-less package URLs.
func Base(value string) string {
	parsed, err := Parse(value)
	if err != nil {
		return ""
	}
	parsed.Version = ""
	parsed.Qualifiers = nil
	parsed.Subpath = ""
	return parsed.String()
}

// Canonical returns the canonical package URL for a package: the existing
// string wins when it canonicalizes, otherwise the parts are built —
// qualifier- and subpath-capable, closing the gap where the legacy fallback
// chain dropped both. This is the primitive the dependency-level identity
// rewrite (ADR-0036) wraps.
func Canonical(existing string, p PURL) string {
	if canonical := Canonicalize(existing); canonical != "" {
		return canonical
	}
	built, err := Build(p)
	if err != nil {
		return ""
	}
	return built
}

// restoreNPMScope restores the '@' prefix on npm scopes. Producers commonly
// record the scope without it, and a scope-less namespace round-trips to a
// different (wrong) identity.
func restoreNPMScope(purl *packageurl.PackageURL) {
	if purl == nil || !strings.EqualFold(strings.TrimSpace(purl.Type), "npm") {
		return
	}
	namespace := strings.TrimSpace(purl.Namespace)
	if namespace != "" && !strings.HasPrefix(namespace, "@") && !strings.HasPrefix(strings.ToLower(namespace), "%40") {
		purl.Namespace = "@" + namespace
	}
}

func fromPackageURL(purl packageurl.PackageURL) PURL {
	out := PURL{
		Type:      purl.Type,
		Namespace: purl.Namespace,
		Name:      purl.Name,
		Version:   purl.Version,
		Subpath:   purl.Subpath,
	}
	for _, q := range purl.Qualifiers {
		out.Qualifiers = append(out.Qualifiers, Qualifier{Key: strings.ToLower(q.Key), Value: q.Value})
	}
	sort.Slice(out.Qualifiers, func(i, j int) bool { return out.Qualifiers[i].Key < out.Qualifiers[j].Key })
	return out
}

func toLibQualifiers(qualifiers []Qualifier) packageurl.Qualifiers {
	if len(qualifiers) == 0 {
		return nil
	}
	out := make(packageurl.Qualifiers, 0, len(qualifiers))
	for _, q := range qualifiers {
		out = append(out, packageurl.Qualifier{Key: strings.TrimSpace(strings.ToLower(q.Key)), Value: q.Value})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
