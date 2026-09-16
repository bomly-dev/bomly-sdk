package plugin

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/bomly-dev/bomly-sdk/model"
)

// ComponentDescriptor describes the common identity and selection fields shared
// by detectors, matchers, auditors, and analyzers.
//
// Name is required and bounded by MaxComponentNameLength; it must be valid
// UTF-8 with no control characters, because it reaches published documents
// where a newline would corrupt SPDX's line-oriented tag form. Whitespace
// inside a name is legal. The checks apply to the value as stored --
// validation does not rewrite it -- so padding counts against the bound.
// The gate is validateComponentDescriptor, through each kind's
// Validate*Descriptor.
type ComponentDescriptor struct {
	Name                string                 `json:"name"`
	DisplayName         string                 `json:"displayName,omitempty"`
	Aliases             []string               `json:"aliases,omitempty"`
	Tags                []string               `json:"tags,omitempty"`
	SupportedEcosystems []model.Ecosystem      `json:"supportedEcosystems,omitempty"`
	SupportedManagers   []model.PackageManager `json:"supportedManagers,omitempty"`
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

// The Base* types below provide default implementations for the optional
// lifecycle methods of the component interfaces (Detector, Matcher, Auditor,
// Analyzer). Go interfaces have no default methods, so any method added to an
// interface is a breaking change for every implementer. Embedding a Base
// struct insulates implementations from that churn: when the SDK grows a new
// optional method, the Base type gains a sensible default and existing
// components keep compiling.
//
// Embed the Base type for your component kind and override only what you
// need:
//
//	type Detector struct {
//		BaseDetector
//	}
//
//	func (Detector) Descriptor() DetectorDescriptor { ... }
//	func (Detector) PackageManagerSupport() []PackageManagerSupport { ... }
//	func (Detector) ResolveGraph(ctx context.Context, req DetectionRequest) (DetectionResult, error) { ... }
//
// Identity (Descriptor) and the component's action method (ResolveGraph,
// Match, Audit, Analyze) have no meaningful default and must always be
// implemented.

// BaseDetector provides default implementations of Detector's optional
// lifecycle methods: always ready and always applicable.
type BaseDetector struct{}

// Ready reports the detector as ready.
func (BaseDetector) Ready(context.Context, DetectionRequest) error { return nil }

// Applicable reports the detector as applicable.
func (BaseDetector) Applicable(context.Context, DetectionRequest) (bool, error) { return true, nil }

// BaseMatcher provides default implementations of Matcher's optional
// lifecycle methods: always ready and always applicable.
type BaseMatcher struct{}

// Ready reports the matcher as ready.
func (BaseMatcher) Ready(context.Context, MatchRequest) error { return nil }

// Applicable reports the matcher as applicable.
func (BaseMatcher) Applicable(context.Context, MatchRequest) (bool, error) { return true, nil }

// BaseAuditor provides default implementations of Auditor's optional
// lifecycle methods: always ready and always applicable.
type BaseAuditor struct{}

// Ready reports the auditor as ready.
func (BaseAuditor) Ready(context.Context, AuditRequest) error { return nil }

// Applicable reports the auditor as applicable.
func (BaseAuditor) Applicable(context.Context, AuditRequest) (bool, error) { return true, nil }

// BaseAnalyzer provides default implementations of Analyzer's optional
// lifecycle methods: always ready and always applicable.
type BaseAnalyzer struct{}

// Ready reports the analyzer as ready.
func (BaseAnalyzer) Ready(context.Context, AnalyzeRequest) error { return nil }

// Applicable reports the analyzer as applicable.
func (BaseAnalyzer) Applicable(context.Context, AnalyzeRequest) (bool, error) { return true, nil }

// ValidateDetectorDescriptor validates typed detector registration data.
func ValidateDetectorDescriptor(descriptor *DetectorDescriptor) error {
	if descriptor == nil {
		return fmt.Errorf("detector descriptor is nil")
	}
	if err := validateComponentDescriptor("detector", componentFromDetectorDescriptor(*descriptor)); err != nil {
		return err
	}
	for _, manager := range descriptor.SupportedManagers {
		if strings.TrimSpace(manager.Name()) == "" {
			return fmt.Errorf("detector descriptor supported managers must not contain empty values")
		}
	}
	for _, support := range descriptor.PackageManagerSupport {
		if strings.TrimSpace(support.PackageManager.Name()) == "" {
			return fmt.Errorf("detector descriptor package manager support must not contain empty package manager values")
		}
	}
	for _, fallback := range descriptor.FallbackDetectors {
		if strings.TrimSpace(fallback) == "" {
			return fmt.Errorf("detector descriptor fallback detectors must not contain empty values")
		}
	}
	for _, capability := range descriptor.RemediationCapabilities {
		if len(capability.SupportedManagers) == 0 {
			return fmt.Errorf("detector descriptor remediation capability must include a package manager")
		}
		for _, manager := range capability.SupportedManagers {
			if strings.TrimSpace(manager.Name()) == "" {
				return fmt.Errorf("detector descriptor remediation capability managers must not contain empty values")
			}
		}
		if len(capability.Actions) == 0 {
			return fmt.Errorf("detector descriptor remediation capability must include an action")
		}
		for _, action := range capability.Actions {
			switch action {
			case model.RemediationActionDirectBump,
				model.RemediationActionTransitiveOverride,
				model.RemediationActionLockfileRefresh:
			default:
				return fmt.Errorf("detector descriptor remediation capability action %q is invalid", action)
			}
		}
	}
	return nil
}

// ValidateMatcherDescriptor validates typed matcher registration data.
func ValidateMatcherDescriptor(descriptor *MatcherDescriptor) error {
	if descriptor == nil {
		return fmt.Errorf("matcher descriptor is nil")
	}
	return validateComponentDescriptor("matcher", componentFromMatcherDescriptor(*descriptor))
}

// ValidateAuditorDescriptor validates typed auditor registration data.
func ValidateAuditorDescriptor(descriptor *AuditorDescriptor) error {
	if descriptor == nil {
		return fmt.Errorf("auditor descriptor is nil")
	}
	return validateComponentDescriptor("auditor", componentFromAuditorDescriptor(*descriptor))
}

// ValidateAnalyzerDescriptor validates typed analyzer registration data.
func ValidateAnalyzerDescriptor(descriptor *AnalyzerDescriptor) error {
	if descriptor == nil {
		return fmt.Errorf("analyzer descriptor is nil")
	}
	return validateComponentDescriptor("analyzer", componentFromAnalyzerDescriptor(*descriptor))
}

func validateComponentDescriptor(kind string, descriptor ComponentDescriptor) error {
	name := strings.TrimSpace(descriptor.Name)
	if name == "" {
		return fmt.Errorf("%s descriptor name is required", kind)
	}
	// The name reaches published documents as a license source, so it is
	// held to the same domain there and here: bounded, valid UTF-8, no
	// control characters. Checked on the stored value, not a trimmed copy:
	// validation does not rewrite the descriptor, so a name that passes here
	// is the name that gets marshaled, and a control character at an edge or
	// unbounded padding would otherwise ride through a gate that claims to
	// refuse them. The source gate trims before it measures, which only
	// shrinks, so every name accepted here still survives there.
	if len(descriptor.Name) > model.MaxComponentNameLength {
		return fmt.Errorf("%s descriptor name exceeds %d bytes", kind, model.MaxComponentNameLength)
	}
	if !utf8.ValidString(descriptor.Name) || model.ContainsControlChar(descriptor.Name) {
		return fmt.Errorf("%s descriptor name must be valid UTF-8 without control characters", kind)
	}
	for _, alias := range descriptor.Aliases {
		if strings.TrimSpace(alias) == "" {
			return fmt.Errorf("%s descriptor aliases must not contain empty values", kind)
		}
	}
	for _, manager := range descriptor.SupportedManagers {
		if strings.TrimSpace(manager.Name()) == "" {
			return fmt.Errorf("%s descriptor supported managers must not contain empty values", kind)
		}
	}
	return nil
}

func componentFromDetectorDescriptor(descriptor DetectorDescriptor) ComponentDescriptor {
	return ComponentDescriptor{Name: descriptor.Name, DisplayName: descriptor.DisplayName, Aliases: descriptor.Aliases, Tags: descriptor.Tags, SupportedEcosystems: descriptor.SupportedEcosystems, SupportedManagers: descriptor.SupportedManagers}
}

func componentFromMatcherDescriptor(descriptor MatcherDescriptor) ComponentDescriptor {
	return ComponentDescriptor{Name: descriptor.Name, DisplayName: descriptor.DisplayName, Aliases: descriptor.Aliases, Tags: descriptor.Tags, SupportedEcosystems: descriptor.SupportedEcosystems, SupportedManagers: descriptor.SupportedManagers}
}

func componentFromAuditorDescriptor(descriptor AuditorDescriptor) ComponentDescriptor {
	return ComponentDescriptor{Name: descriptor.Name, DisplayName: descriptor.DisplayName, Aliases: descriptor.Aliases, Tags: descriptor.Tags, SupportedEcosystems: descriptor.SupportedEcosystems, SupportedManagers: descriptor.SupportedManagers}
}

func componentFromAnalyzerDescriptor(descriptor AnalyzerDescriptor) ComponentDescriptor {
	return ComponentDescriptor{Name: descriptor.Name, DisplayName: descriptor.DisplayName, Aliases: descriptor.Aliases, Tags: descriptor.Tags, SupportedEcosystems: descriptor.SupportedEcosystems, SupportedManagers: descriptor.SupportedManagers}
}

func includesComponentName(include []string, name string) bool {
	if len(include) == 0 {
		return true
	}
	return slices.Contains(include, name)
}

func excludesComponentName(exclude []string, name string) bool {
	return slices.Contains(exclude, name)
}
