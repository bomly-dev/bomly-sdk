package sdk

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

// ExecutionMode identifies how a component instance is being executed.
type ExecutionMode string

const (
	// ExecutionEmbedded marks a component compiled into the host binary and
	// registered in-process.
	ExecutionEmbedded ExecutionMode = "embedded"
	// ExecutionManaged marks a component running in its own plugin process
	// managed by the host over the plugin transport.
	ExecutionManaged ExecutionMode = "managed"
)

// RuntimeInfo describes the host runtime a component executes under.
type RuntimeInfo struct {
	// CoreVersion is the host core version when known; empty otherwise.
	CoreVersion string
	// Execution reports whether the component runs embedded or managed.
	Execution ExecutionMode
}

// HostContext is the only channel through which a component reaches host
// services. The same contract is satisfied by the embedded host (in-process
// registration) and the managed host (plugin subprocess), so a component
// written against it runs unchanged in both execution modes.
type HostContext interface {
	Logger() *zap.Logger
	HTTPClient() *HTTPClientProvider
	Runtime() RuntimeInfo
	// DecodeConfig unmarshals the component's own configuration block into v.
	// Embedded execution sources it from the host config's kind-scoped
	// plugins.<kind>.<name> block; managed execution sources it from the
	// config file the host passes via BOMLY_PLUGIN_CONFIG_FILE. Identical
	// JSON semantics both ways.
	DecodeConfig(v any) error
}

// DetectorModule declares one detector component: its static descriptor,
// package-manager support, and a constructor invoked once per execution.
type DetectorModule struct {
	Descriptor DetectorDescriptor
	Support    []PackageManagerSupport
	New        func(context.Context, HostContext) (Detector, error)
}

// MatcherModule declares one matcher component.
type MatcherModule struct {
	Descriptor MatcherDescriptor
	New        func(context.Context, HostContext) (Matcher, error)
}

// AuditorModule declares one auditor component.
type AuditorModule struct {
	Descriptor AuditorDescriptor
	New        func(context.Context, HostContext) (Auditor, error)
}

// AnalyzerModule declares one analyzer component.
type AnalyzerModule struct {
	Descriptor AnalyzerDescriptor
	New        func(context.Context, HostContext) (Analyzer, error)
}

// Module is the execution-neutral packaging of one component. Exactly one of
// the role fields must be set, and it must match Kind. The same Module value
// can be registered embedded by the host or served managed via ServeModule.
type Module struct {
	Kind     PluginKind
	Detector *DetectorModule
	Matcher  *MatcherModule
	Auditor  *AuditorModule
	Analyzer *AnalyzerModule
}

// ValidateModule checks that exactly one role is set, that the role matches
// the declared Kind, that the role constructor is present, and that the role
// descriptor validates.
func ValidateModule(m Module) error {
	roles := 0
	if m.Detector != nil {
		roles++
	}
	if m.Matcher != nil {
		roles++
	}
	if m.Auditor != nil {
		roles++
	}
	if m.Analyzer != nil {
		roles++
	}
	if roles != 1 {
		return fmt.Errorf("module must set exactly one role, got %d", roles)
	}

	switch m.Kind {
	case PluginKindDetector:
		if m.Detector == nil {
			return fmt.Errorf("module kind %q requires the Detector role", m.Kind)
		}
		if m.Detector.New == nil {
			return fmt.Errorf("detector module constructor is required")
		}
		if err := ValidateDetectorDescriptor(&m.Detector.Descriptor); err != nil {
			return fmt.Errorf("detector module descriptor: %w", err)
		}
		for _, support := range m.Detector.Support {
			if support.PackageManager.Name() == "" {
				return fmt.Errorf("detector module support must not contain empty package manager values")
			}
		}
	case PluginKindMatcher:
		if m.Matcher == nil {
			return fmt.Errorf("module kind %q requires the Matcher role", m.Kind)
		}
		if m.Matcher.New == nil {
			return fmt.Errorf("matcher module constructor is required")
		}
		if err := ValidateMatcherDescriptor(&m.Matcher.Descriptor); err != nil {
			return fmt.Errorf("matcher module descriptor: %w", err)
		}
	case PluginKindAuditor:
		if m.Auditor == nil {
			return fmt.Errorf("module kind %q requires the Auditor role", m.Kind)
		}
		if m.Auditor.New == nil {
			return fmt.Errorf("auditor module constructor is required")
		}
		if err := ValidateAuditorDescriptor(&m.Auditor.Descriptor); err != nil {
			return fmt.Errorf("auditor module descriptor: %w", err)
		}
	case PluginKindAnalyzer:
		if m.Analyzer == nil {
			return fmt.Errorf("module kind %q requires the Analyzer role", m.Kind)
		}
		if m.Analyzer.New == nil {
			return fmt.Errorf("analyzer module constructor is required")
		}
		if err := ValidateAnalyzerDescriptor(&m.Analyzer.Descriptor); err != nil {
			return fmt.Errorf("analyzer module descriptor: %w", err)
		}
	default:
		return fmt.Errorf("module kind %q is invalid", m.Kind)
	}
	return nil
}
