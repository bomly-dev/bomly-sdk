package runtime

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/bomly-dev/bomly-sdk/httpkit"

	"github.com/bomly-dev/bomly-sdk/plugin"
)

// EnvVerbosity mirrors the host's verbosity environment variable
// (0 = normal, 1 = verbose, 2+ = debug). Managed components derive their
// stderr log level from it when present.
const EnvVerbosity = "BOMLY_VERBOSE"

// ServeModule serves one Module as a managed plugin over Bomly's HashiCorp
// go-plugin gRPC transport. Call it from the plugin binary's main function.
// It validates the module, builds a managed HostContext (stderr logger, HTTP
// client provider from Bomly environment variables, config decoding from the
// file named by BOMLY_PLUGIN_CONFIG_FILE), constructs the component lazily on
// first use, and adapts it to the served plugin protocol.
//
// The component's lifetime is the process's. Its constructor runs under a
// context that outlives any one request, and the cleanups it registers
// through HostContext.OnCleanup run when the host shuts the plugin down: the
// host's go-plugin client closes the connection, the transport stops
// serving, and ServeModule closes the scope before it returns -- inside the
// grace period the client allows before it kills the process. No RPC carries
// this, so a host of any SDK version gets it.
func ServeModule(m plugin.Module) {
	if err := plugin.ValidateModule(m); err != nil {
		fmt.Fprintf(os.Stderr, "bomly plugin: invalid module: %v\n", err)
		os.Exit(1)
	}
	host := newManagedHostContext(moduleName(m))
	switch m.Kind {
	case plugin.PluginKindDetector:
		ServeDetector(newServedDetectorModule(m.Detector, host))
	case plugin.PluginKindMatcher:
		ServeMatcher(newServedMatcherModule(m.Matcher, host))
	case plugin.PluginKindAuditor:
		ServeAuditor(newServedAuditorModule(m.Auditor, host))
	case plugin.PluginKindAnalyzer:
		ServeAnalyzer(newServedAnalyzerModule(m.Analyzer, host))
	}
	if err := host.scope.Close(); err != nil {
		host.Logger().Warn("bomly plugin: component cleanup failed", zap.Error(err))
	}
}

// moduleName is the component name a module's cleanup errors carry.
func moduleName(m plugin.Module) string {
	switch {
	case m.Detector != nil:
		return m.Detector.Descriptor.Name
	case m.Matcher != nil:
		return m.Matcher.Descriptor.Name
	case m.Auditor != nil:
		return m.Auditor.Descriptor.Name
	case m.Analyzer != nil:
		return m.Analyzer.Descriptor.Name
	default:
		return string(m.Kind)
	}
}

// managedHostContext implements HostContext for components running as managed
// plugin subprocesses.
type managedHostContext struct {
	logger  *zap.Logger
	http    *httpkit.ClientProvider
	runtime plugin.RuntimeInfo
	scope   *plugin.ComponentScope
}

func newManagedHostContext(component string) *managedHostContext {
	logger := newManagedLogger()
	provider, err := httpkit.NewClientProviderFromEnv()
	if err != nil {
		logger.Warn("bomly plugin: HTTP client environment configuration invalid; using defaults", zap.Error(err))
		provider, _ = httpkit.NewClientProvider(httpkit.ClientConfig{})
	}
	return &managedHostContext{
		logger:  logger,
		http:    provider,
		runtime: plugin.RuntimeInfo{Execution: plugin.ExecutionManaged},
		scope:   plugin.NewComponentScope(context.Background(), component),
	}
}

// OnCleanup registers fn on the process-lifetime scope ServeModule closes.
func (c *managedHostContext) OnCleanup(fn func() error) {
	c.scope.OnCleanup(fn)
}

// lifetime is the context a component is constructed under.
func (c *managedHostContext) lifetime() context.Context {
	return c.scope.Context()
}

func (c *managedHostContext) Logger() *zap.Logger {
	if c == nil || c.logger == nil {
		return zap.NewNop()
	}
	return c.logger
}

func (c *managedHostContext) HTTPClient() *httpkit.ClientProvider {
	if c == nil {
		return nil
	}
	return c.http
}

func (c *managedHostContext) Runtime() plugin.RuntimeInfo {
	if c == nil {
		return plugin.RuntimeInfo{Execution: plugin.ExecutionManaged}
	}
	return c.runtime
}

func (c *managedHostContext) DecodeConfig(v any) error {
	return DecodePluginConfigFromEnv(v)
}

// newManagedLogger builds a stderr logger for a managed plugin process. The
// level is derived from the host's verbosity environment variable when set
// (2+ enables debug), and defaults to Info otherwise.
func newManagedLogger() *zap.Logger {
	level := zapcore.InfoLevel
	if raw := strings.TrimSpace(os.Getenv(EnvVerbosity)); raw != "" {
		if verbosity, err := strconv.Atoi(raw); err == nil && verbosity >= 2 {
			level = zapcore.DebugLevel
		}
	}
	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(level)
	config.OutputPaths = []string{"stderr"}
	config.ErrorOutputPaths = []string{"stderr"}
	logger, err := config.Build()
	if err != nil {
		return zap.NewNop()
	}
	return logger
}

// lazyComponent constructs a module component at most once and caches the
// outcome for every subsequent protocol call.
//
// Construction runs under the component's lifetime context, not the context
// of the request that happened to need it first: a constructor that ties a
// resource to its context must not see that resource cancelled when the
// first RPC returns. A request waits for construction as long as its own
// context allows; giving up abandons the wait, not the construction, so the
// next request finds the component built.
type lazyComponent[T any] struct {
	newFn func(context.Context, plugin.HostContext) (T, error)
	host  plugin.HostContext

	once      sync.Once
	done      chan struct{}
	component T
	err       error
}

// lifetimeHost is the managed host's view of a component's lifetime.
type lifetimeHost interface {
	lifetime() context.Context
}

func (l *lazyComponent[T]) get(ctx context.Context) (T, error) {
	l.once.Do(func() {
		lifetime := context.Background()
		if host, ok := l.host.(lifetimeHost); ok {
			lifetime = host.lifetime()
		}
		l.done = make(chan struct{})
		go func() {
			defer close(l.done)
			l.component, l.err = construct(lifetime, l.newFn, l.host)
		}()
	})
	select {
	case <-l.done:
		return l.component, l.err
	case <-ctx.Done():
		var zero T
		return zero, fmt.Errorf("construct component: %w", ctx.Err())
	}
}

// construct runs a module constructor, containing a panic as a constructor
// error: it runs on its own goroutine, where a panic would end the process.
func construct[T any](ctx context.Context, newFn func(context.Context, plugin.HostContext) (T, error), host plugin.HostContext) (component T, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("construct component: panic: %v", recovered)
		}
	}()
	component, err = newFn(ctx, host)
	if err != nil {
		err = fmt.Errorf("construct component: %w", err)
	}
	return component, err
}

// readyResponseFromError maps a component's Ready error contract (nil = ready)
// to the served protocol's ReadyResponse shape.
func readyResponseFromError(err error) *plugin.ReadyResponse {
	if err != nil {
		return &plugin.ReadyResponse{Ready: false, Reason: err.Error()}
	}
	return &plugin.ReadyResponse{Ready: true}
}

// servedDetectorModule adapts a DetectorModule to the ServedDetector protocol.
type servedDetectorModule struct {
	module *plugin.DetectorModule
	lazy   *lazyComponent[plugin.Detector]
}

func newServedDetectorModule(module *plugin.DetectorModule, host plugin.HostContext) *servedDetectorModule {
	return &servedDetectorModule{
		module: module,
		lazy:   &lazyComponent[plugin.Detector]{newFn: module.New, host: host},
	}
}

func (s *servedDetectorModule) Descriptor(context.Context) (*plugin.DetectorDescriptor, error) {
	descriptor := s.module.Descriptor.Clone()
	return &descriptor, nil
}

func (s *servedDetectorModule) PackageManagerSupport(ctx context.Context) ([]plugin.PackageManagerSupport, error) {
	if len(s.module.Support) > 0 {
		support := make([]plugin.PackageManagerSupport, len(s.module.Support))
		for idx, entry := range s.module.Support {
			support[idx] = entry
			support[idx].EvidencePatterns = append([]string(nil), entry.EvidencePatterns...)
		}
		return support, nil
	}
	detector, err := s.lazy.get(ctx)
	if err != nil {
		return nil, err
	}
	return detector.PackageManagerSupport(), nil
}

func (s *servedDetectorModule) Ready(ctx context.Context, req *plugin.DetectRequest) (*plugin.ReadyResponse, error) {
	detector, err := s.lazy.get(ctx)
	if err != nil {
		return nil, err
	}
	return readyResponseFromError(detector.Ready(ctx, *req)), nil
}

func (s *servedDetectorModule) Applicable(ctx context.Context, req *plugin.DetectRequest) (*plugin.ApplicableResponse, error) {
	detector, err := s.lazy.get(ctx)
	if err != nil {
		return nil, err
	}
	applicable, err := detector.Applicable(ctx, *req)
	if err != nil {
		return nil, err
	}
	return &plugin.ApplicableResponse{Applicable: applicable}, nil
}

func (s *servedDetectorModule) Detect(ctx context.Context, req *plugin.DetectRequest) (*plugin.DetectResponse, error) {
	detector, err := s.lazy.get(ctx)
	if err != nil {
		return nil, err
	}
	result, err := detector.ResolveGraph(ctx, *req)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// Install satisfies DetectorInstaller. Components that do not implement
// InstallFirstDetector report no install work performed.
func (s *servedDetectorModule) Install(ctx context.Context, req *plugin.DetectRequest) (*plugin.InstallResponse, error) {
	detector, err := s.lazy.get(ctx)
	if err != nil {
		return nil, err
	}
	installer, ok := detector.(plugin.InstallFirstDetector)
	if !ok {
		return &plugin.InstallResponse{}, nil
	}
	if err := installer.Install(ctx, *req); err != nil {
		return nil, err
	}
	return &plugin.InstallResponse{Performed: true}, nil
}

// servedMatcherModule adapts a MatcherModule to the ServedMatcher protocol.
type servedMatcherModule struct {
	module *plugin.MatcherModule
	lazy   *lazyComponent[plugin.Matcher]
}

func newServedMatcherModule(module *plugin.MatcherModule, host plugin.HostContext) *servedMatcherModule {
	return &servedMatcherModule{
		module: module,
		lazy:   &lazyComponent[plugin.Matcher]{newFn: module.New, host: host},
	}
}

func (s *servedMatcherModule) Descriptor(context.Context) (*plugin.MatcherDescriptor, error) {
	descriptor := s.module.Descriptor.Clone()
	return &descriptor, nil
}

func (s *servedMatcherModule) Ready(ctx context.Context, req *plugin.MatchRequest) (*plugin.ReadyResponse, error) {
	matcher, err := s.lazy.get(ctx)
	if err != nil {
		return nil, err
	}
	return readyResponseFromError(matcher.Ready(ctx, *req)), nil
}

func (s *servedMatcherModule) Applicable(ctx context.Context, req *plugin.MatchRequest) (*plugin.ApplicableResponse, error) {
	matcher, err := s.lazy.get(ctx)
	if err != nil {
		return nil, err
	}
	applicable, err := matcher.Applicable(ctx, *req)
	if err != nil {
		return nil, err
	}
	return &plugin.ApplicableResponse{Applicable: applicable}, nil
}

func (s *servedMatcherModule) Match(ctx context.Context, req *plugin.MatchRequest) (*plugin.MatchResponse, error) {
	matcher, err := s.lazy.get(ctx)
	if err != nil {
		return nil, err
	}
	result, err := matcher.Match(ctx, *req)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// servedAuditorModule adapts an AuditorModule to the ServedAuditor protocol.
type servedAuditorModule struct {
	module *plugin.AuditorModule
	lazy   *lazyComponent[plugin.Auditor]
}

func newServedAuditorModule(module *plugin.AuditorModule, host plugin.HostContext) *servedAuditorModule {
	return &servedAuditorModule{
		module: module,
		lazy:   &lazyComponent[plugin.Auditor]{newFn: module.New, host: host},
	}
}

func (s *servedAuditorModule) Descriptor(context.Context) (*plugin.AuditorDescriptor, error) {
	descriptor := s.module.Descriptor.Clone()
	return &descriptor, nil
}

func (s *servedAuditorModule) Ready(ctx context.Context, req *plugin.AuditRequest) (*plugin.ReadyResponse, error) {
	auditor, err := s.lazy.get(ctx)
	if err != nil {
		return nil, err
	}
	return readyResponseFromError(auditor.Ready(ctx, *req)), nil
}

func (s *servedAuditorModule) Applicable(ctx context.Context, req *plugin.AuditRequest) (*plugin.ApplicableResponse, error) {
	auditor, err := s.lazy.get(ctx)
	if err != nil {
		return nil, err
	}
	applicable, err := auditor.Applicable(ctx, *req)
	if err != nil {
		return nil, err
	}
	return &plugin.ApplicableResponse{Applicable: applicable}, nil
}

func (s *servedAuditorModule) Audit(ctx context.Context, req *plugin.AuditRequest) (*plugin.AuditResponse, error) {
	auditor, err := s.lazy.get(ctx)
	if err != nil {
		return nil, err
	}
	result, err := auditor.Audit(ctx, *req)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// servedAnalyzerModule adapts an AnalyzerModule to the ServedAnalyzer protocol.
type servedAnalyzerModule struct {
	module *plugin.AnalyzerModule
	lazy   *lazyComponent[plugin.Analyzer]
}

func newServedAnalyzerModule(module *plugin.AnalyzerModule, host plugin.HostContext) *servedAnalyzerModule {
	return &servedAnalyzerModule{
		module: module,
		lazy:   &lazyComponent[plugin.Analyzer]{newFn: module.New, host: host},
	}
}

func (s *servedAnalyzerModule) Descriptor(context.Context) (*plugin.AnalyzerDescriptor, error) {
	descriptor := s.module.Descriptor.Clone()
	return &descriptor, nil
}

func (s *servedAnalyzerModule) Ready(ctx context.Context, req *plugin.AnalyzeRequest) (*plugin.ReadyResponse, error) {
	analyzer, err := s.lazy.get(ctx)
	if err != nil {
		return nil, err
	}
	return readyResponseFromError(analyzer.Ready(ctx, *req)), nil
}

func (s *servedAnalyzerModule) Applicable(ctx context.Context, req *plugin.AnalyzeRequest) (*plugin.ApplicableResponse, error) {
	analyzer, err := s.lazy.get(ctx)
	if err != nil {
		return nil, err
	}
	applicable, err := analyzer.Applicable(ctx, *req)
	if err != nil {
		return nil, err
	}
	return &plugin.ApplicableResponse{Applicable: applicable}, nil
}

func (s *servedAnalyzerModule) Analyze(ctx context.Context, req *plugin.AnalyzeRequest) (*plugin.AnalyzeResponse, error) {
	analyzer, err := s.lazy.get(ctx)
	if err != nil {
		return nil, err
	}
	result, err := analyzer.Analyze(ctx, *req)
	if err != nil {
		return nil, err
	}
	return &result, nil
}
