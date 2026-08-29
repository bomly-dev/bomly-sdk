package purlkit

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/package-url/packageurl-go"
)

// ErrInvalidPURL reports a package URL that cannot be built or parsed. Every
// failure from Parse, Build, and their derivatives matches it with errors.Is,
// including failures surfaced by the underlying parser.
var ErrInvalidPURL = errors.New("invalid package URL")

// maxInputSize bounds untrusted input before parsing (the repository's fuzz
// convention, enforced in production here because package URLs arrive from
// untrusted SBOMs and registry responses).
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
	if value == "" || len(value) > maxInputSize {
		return PURL{}, ErrInvalidPURL
	}
	parsed, err := packageurl.FromString(value)
	if err != nil {
		return PURL{}, fmt.Errorf("%w: %v", ErrInvalidPURL, err)
	}
	if _, err := normalizeAndRender(&parsed); err != nil {
		return PURL{}, err
	}
	return fromPackageURL(parsed), nil
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
// root builder cannot do. The output is a Parse fixed point.
func Build(p PURL) (string, error) {
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
	return normalizeAndRender(built)
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

// normalizeAndRender applies the two Bomly boundary policies that compose
// with packageurl-go normalization: surrounding field whitespace is ignored,
// and npm producer scopes missing their '@' prefix are repaired. The library
// remains responsible for PURL validation, type rules, and canonical
// rendering.
func normalizeAndRender(purl *packageurl.PackageURL) (string, error) {
	if purl == nil {
		return "", ErrInvalidPURL
	}
	purl.Namespace = trimPathBoundary(purl.Namespace)
	purl.Subpath = trimPathBoundary(purl.Subpath)
	restoreNPMScope(purl)
	if err := purl.Normalize(); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidPURL, err)
	}
	// The whitespace boundary policy makes a blank-after-trim name invalid on
	// Build; Parse must agree, or a parsed value fails to re-render and the
	// Parse→String fixed point breaks (found by FuzzSplitIdentity on
	// "pkg:A/ #").
	if strings.TrimSpace(purl.Name) == "" {
		return "", fmt.Errorf("%w: name is blank after trimming", ErrInvalidPURL)
	}
	rendered := purl.ToString()
	if len(rendered) > maxInputSize {
		return "", ErrInvalidPURL
	}
	return rendered, nil
}

func trimPathBoundary(value string) string {
	return strings.TrimFunc(value, func(r rune) bool {
		return r == '/' || unicode.IsSpace(r)
	})
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
