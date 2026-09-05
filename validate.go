package sdk

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

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
			case RemediationActionDirectBump,
				RemediationActionTransitiveOverride,
				RemediationActionLockfileRefresh:
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
	if len(descriptor.Name) > maxComponentNameLength {
		return fmt.Errorf("%s descriptor name exceeds %d bytes", kind, maxComponentNameLength)
	}
	if !utf8.ValidString(descriptor.Name) || containsControlChar(descriptor.Name) {
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
