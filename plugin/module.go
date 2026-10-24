package plugin

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/httpkit"
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
	HTTPClient() *httpkit.ClientProvider
	Runtime() RuntimeInfo
	// DecodeConfig unmarshals the component's own configuration block into v.
	// Embedded execution sources it from the host config's kind-scoped
	// plugins.<kind>.<name> block; managed execution sources it from the
	// config file the host passes via BOMLY_PLUGIN_CONFIG_FILE. Identical
	// JSON semantics both ways.
	DecodeConfig(v any) error
	// OnCleanup registers fn to run once when the component's lifetime
	// ends, after the constructor's context is cancelled. Cleanups run in
	// reverse registration order, each at most once, and every one runs
	// even when an earlier one fails or panics; the failures are joined.
	// Register right after acquiring each resource -- a file, a temporary
	// directory, a goroutine, an idle HTTP transport -- so a constructor
	// that fails afterwards still releases what it acquired.
	//
	// Embedded, the lifetime is the host command's. Managed, it is the
	// plugin process's: cleanups run when the host shuts the plugin down,
	// within the transport's grace period, and not at all if the process is
	// killed outright. A cleanup registered after the lifetime has ended
	// runs at once. ComponentScope implements this for a host.
	OnCleanup(fn func() error)
}

// ComponentScope is one component's lifetime: the context its constructor
// receives, and the cleanups it registers through HostContext.OnCleanup. A
// host creates one per component, passes Context to the module's New, and
// calls Close exactly when the component can no longer be used -- at the
// end of the command embedded, when the plugin is shut down managed -- so a
// component releases its resources the same way in both execution modes.
// The zero value is not usable; construct one with NewComponentScope.
type ComponentScope struct {
	component string
	ctx       context.Context
	cancel    context.CancelFunc

	mu       sync.Mutex
	cleanups []func() error
	closed   bool
	closeErr error
}

// NewComponentScope starts a lifetime for the named component, derived from
// parent: cancelling parent cancels the scope's context, but only Close runs
// the cleanups. The name prefixes every cleanup error.
func NewComponentScope(parent context.Context, component string) *ComponentScope {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	return &ComponentScope{component: component, ctx: ctx, cancel: cancel}
}

// Context returns the component's lifetime context: the one to pass to a
// module's New. It is cancelled when Close begins or when the parent is.
func (s *ComponentScope) Context() context.Context {
	return s.ctx
}

// OnCleanup registers fn to run when the scope closes. After Close it runs
// fn at once, so a constructor still running when its lifetime ended --
// cancelled mid-construction -- does not leak what it acquired late; that
// call's error has no Close left to report it and is dropped. A nil fn is
// ignored.
func (s *ComponentScope) OnCleanup(fn func() error) {
	if fn == nil {
		return
	}
	s.mu.Lock()
	if !s.closed {
		s.cleanups = append(s.cleanups, fn)
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	_ = runCleanup(fn)
}

// Close ends the lifetime: it cancels the scope's context, then runs every
// registered cleanup in reverse registration order, each at most once. A
// cleanup that fails or panics does not stop the rest; the failures are
// joined, each prefixed with the component name. A second Close runs
// nothing and returns the first Close's error.
func (s *ComponentScope) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return s.closeErr
	}
	s.closed = true
	cleanups := s.cleanups
	s.cleanups = nil
	s.mu.Unlock()

	s.cancel()
	var errs []error
	for i := len(cleanups) - 1; i >= 0; i-- {
		if err := runCleanup(cleanups[i]); err != nil {
			errs = append(errs, fmt.Errorf("%s: cleanup: %w", s.component, err))
		}
	}
	err := errors.Join(errs...)
	s.mu.Lock()
	s.closeErr = err
	s.mu.Unlock()
	return err
}

// runCleanup calls fn, containing a panic as an error so one broken cleanup
// cannot keep the others from running or crash the host.
func runCleanup(fn func() error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("panic: %v", recovered)
		}
	}()
	return fn()
}

// DetectorModule declares one detector component: its static descriptor,
// package-manager support, and a constructor invoked once per execution.
type DetectorModule struct {
	Descriptor DetectorDescriptor
	Support    []PackageManagerSupport
	// TargetKinds lists the execution target kinds the detector supports.
	// Empty means the host derives the default [filesystem, git-repository],
	// mirroring the managed-plugin derivation.
	TargetKinds []ExecutionTargetKind
	New         func(context.Context, HostContext) (Detector, error)
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
// can be registered embedded by the host or served managed via plugin.ServeModule.
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
		for _, kind := range m.Detector.TargetKinds {
			if string(kind) == "" {
				return fmt.Errorf("detector module target kinds must not contain empty values")
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
