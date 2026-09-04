package sdk

import "strings"

// maxComponentNameLength bounds a component descriptor name, in bytes.
//
// A component name is not only a registry key: it is written verbatim into
// published output as the source of a license claim (PackageLicense.Source),
// so its domain is what publication can carry. The two gates used to disagree
// -- descriptor validation asked only that a name be non-blank, while the
// license source was bounded -- so a 257-byte matcher was a valid component
// whose provenance the source gate silently erased. maxLicenseSourceLength
// references this constant so the two cannot drift again.
//
// 256 bytes: a real component name is a few dozen characters, and the
// allowance covers a long descriptive one without admitting a value that is
// really a payload. The bound is a resource limit and stays a dumb one.
const maxComponentNameLength = 256

// ComponentDescriptor describes the common identity and selection fields shared
// by detectors, matchers, auditors, and analyzers.
//
// Name is required and bounded by maxComponentNameLength; it must be valid
// UTF-8 with no control characters, because it reaches published documents
// where a newline would corrupt SPDX's line-oriented tag form. Whitespace
// inside a name is legal. The gate is validateComponentDescriptor, through
// each kind's Validate*Descriptor.
type ComponentDescriptor struct {
	Name                string           `json:"name"`
	DisplayName         string           `json:"displayName,omitempty"`
	Aliases             []string         `json:"aliases,omitempty"`
	Tags                []string         `json:"tags,omitempty"`
	SupportedEcosystems []Ecosystem      `json:"supportedEcosystems,omitempty"`
	SupportedManagers   []PackageManager `json:"supportedManagers,omitempty"`
}

// Label returns the user-facing component label, falling back to Name.
func (d ComponentDescriptor) Label() string {
	if value := strings.TrimSpace(d.DisplayName); value != "" {
		return value
	}
	return strings.TrimSpace(d.Name)
}

func componentLabel(name, displayName string) string {
	if value := strings.TrimSpace(displayName); value != "" {
		return value
	}
	return strings.TrimSpace(name)
}

// Label returns the user-facing detector label, falling back to Name.
func (d DetectorDescriptor) Label() string { return componentLabel(d.Name, d.DisplayName) }

// Label returns the user-facing matcher label, falling back to Name.
func (d MatcherDescriptor) Label() string { return componentLabel(d.Name, d.DisplayName) }

// Label returns the user-facing auditor label, falling back to Name.
func (d AuditorDescriptor) Label() string { return componentLabel(d.Name, d.DisplayName) }

// Label returns the user-facing analyzer label, falling back to Name.
func (d AnalyzerDescriptor) Label() string { return componentLabel(d.Name, d.DisplayName) }
