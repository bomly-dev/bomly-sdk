package purlkit

import "fmt"

// typeProfile records the structural requirements a purl type's specification
// states beyond generic purl syntax. The table below is transcribed from the
// machine-readable per-type definitions in the purl specification repository
// (https://github.com/package-url/purl-spec/tree/main/types, the
// *-definition.json documents; transcribed 2026-08-29) and deliberately
// contains only the rules the packageurl-go library does NOT already enforce
// — the library enforces namespace-required for swift and vscode-extension,
// namespace-prohibited for chrome-extension, julia, otp, and vcpkg, and
// julia's required uuid qualifier, so those rows are omitted here rather
// than duplicated. Types absent from both the table and the library's rules
// validate on generic syntax alone: the purl type vocabulary is open by
// design, and an unknown type — a custom ecosystem's own purl type — is
// first-class, never rejected for being unknown.
type typeProfile struct {
	namespaceRequired   bool
	namespaceProhibited bool
	requiredQualifiers  []string
}

var typeProfiles = map[string]typeProfile{
	// Namespace required by the type's specification.
	"alpm":        {namespaceRequired: true},
	"apk":         {namespaceRequired: true},
	"bitbucket":   {namespaceRequired: true},
	"composer":    {namespaceRequired: true},
	"deb":         {namespaceRequired: true},
	"git":         {namespaceRequired: true},
	"github":      {namespaceRequired: true},
	"golang":      {namespaceRequired: true},
	"huggingface": {namespaceRequired: true},
	"maven":       {namespaceRequired: true},
	"qpkg":        {namespaceRequired: true},
	"rpm":         {namespaceRequired: true},

	// Namespace prohibited by the type's specification.
	"bazel":     {namespaceProhibited: true},
	"bitnami":   {namespaceProhibited: true},
	"cargo":     {namespaceProhibited: true},
	"cocoapods": {namespaceProhibited: true},
	"conda":     {namespaceProhibited: true},
	"cran":      {namespaceProhibited: true},
	"gem":       {namespaceProhibited: true},
	"hackage":   {namespaceProhibited: true},
	"mlflow":    {namespaceProhibited: true},
	"nuget":     {namespaceProhibited: true},
	"oci":       {namespaceProhibited: true},
	"opam":      {namespaceProhibited: true},
	"pub":       {namespaceProhibited: true},
	"pypi":      {namespaceProhibited: true},

	// Qualifiers the type's specification marks required.
	"swid": {requiredQualifiers: []string{"tag_id"}},
}

// Validate reports whether the package URL satisfies its type's
// specification profile on top of the library's own syntactic and
// structural rules. The library remains the first gate — the parts must
// build and render canonically — and the profile table adds only the
// spec-stated requirements the library skips (a Maven group ID as the
// namespace, for example). A type with no profile and no library rule
// passes on syntax alone: custom purl types are first-class.
func Validate(p PURL) error {
	rendered, err := Build(p)
	if err != nil {
		return err
	}
	canonical, err := Parse(rendered)
	if err != nil {
		return err
	}
	profile, ok := typeProfiles[canonical.Type]
	if !ok {
		return nil
	}
	if profile.namespaceRequired && canonical.Namespace == "" {
		return fmt.Errorf("%w: type %q requires a namespace", ErrInvalidPURL, canonical.Type)
	}
	if profile.namespaceProhibited && canonical.Namespace != "" {
		return fmt.Errorf("%w: type %q prohibits a namespace", ErrInvalidPURL, canonical.Type)
	}
	for _, required := range profile.requiredQualifiers {
		found := false
		for _, qualifier := range canonical.Qualifiers {
			if qualifier.Key == required {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: type %q requires the %q qualifier", ErrInvalidPURL, canonical.Type, required)
		}
	}
	return nil
}

// ValidateString parses and profile-validates an untrusted package URL
// string in one step.
func ValidateString(value string) error {
	parsed, err := Parse(value)
	if err != nil {
		return err
	}
	return Validate(parsed)
}

// WithoutVersion strips the version from a package URL, keeping qualifiers
// and subpath — the grouping key for version-change detection, where two
// architectures of one package must not read as a version pair. Returns ""
// when the value does not parse.
func WithoutVersion(value string) string {
	parsed, err := Parse(value)
	if err != nil {
		return ""
	}
	parsed.Version = ""
	return parsed.String()
}
