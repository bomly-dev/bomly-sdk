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

	sdk "github.com/bomly-dev/bomly-sdk"
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
func ServeModule(m sdk.Module) {
	if err := sdk.ValidateModule(m); err != nil {
		fmt.Fprintf(os.Stderr, "bomly plugin: invalid module: %v\n", err)
		os.Exit(1)
	}
	host := newManagedHostContext()
	switch m.Kind {
	case sdk.PluginKindDetector:
		ServeDetector(newServedDetectorModule(m.Detector, host))
	case sdk.PluginKindMatcher:
		ServeMatcher(newServedMatcherModule(m.Matcher, host))
	case sdk.PluginKindAuditor:
		ServeAuditor(newServedAuditorModule(m.Auditor, host))
	case sdk.PluginKindAnalyzer:
		ServeAnalyzer(newServedAnalyzerModule(m.Analyzer, host))
	}
}

// managedHostContext implements HostContext for components running as managed
// plugin subprocesses.
type managedHostContext struct {
	logger  *zap.Logger
	http    *httpkit.ClientProvider
	runtime sdk.RuntimeInfo
}

func newManagedHostContext() *managedHostContext {
	logger := newManagedLogger()
	provider, err := httpkit.NewClientProviderFromEnv()
	if err != nil {
		logger.Warn("bomly plugin: HTTP client environment configuration invalid; using defaults", zap.Error(err))
		provider, _ = httpkit.NewClientProvider(httpkit.ClientConfig{})
	}
	return &managedHostContext{
		logger:  logger,
		http:    provider,
		runtime: sdk.RuntimeInfo{Execution: sdk.ExecutionManaged},
	}
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

func (c *managedHostContext) Runtime() sdk.RuntimeInfo {
	if c == nil {
		return sdk.RuntimeInfo{Execution: sdk.ExecutionManaged}
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
type lazyComponent[T any] struct {
	newFn func(context.Context, sdk.HostContext) (T, error)
	host  sdk.HostContext

	once      sync.Once
	component T
	err       error
}

func (l *lazyComponent[T]) get(ctx context.Context) (T, error) {
	l.once.Do(func() {
		l.component, l.err = l.newFn(ctx, l.host)
		if l.err != nil {
			l.err = fmt.Errorf("construct component: %w", l.err)
		}
	})
	return l.component, l.err
}

// readyResponseFromError maps a component's Ready error contract (nil = ready)
// to the served protocol's ReadyResponse shape.
func readyResponseFromError(err error) *sdk.ReadyResponse {
	if err != nil {
		return &sdk.ReadyResponse{Ready: false, Reason: err.Error()}
	}
	return &sdk.ReadyResponse{Ready: true}
}

// servedDetectorModule adapts a DetectorModule to the ServedDetector protocol.
type servedDetectorModule struct {
	module *sdk.DetectorModule
	lazy   *lazyComponent[sdk.Detector]
}

func newServedDetectorModule(module *sdk.DetectorModule, host sdk.HostContext) *servedDetectorModule {
	return &servedDetectorModule{
		module: module,
		lazy:   &lazyComponent[sdk.Detector]{newFn: module.New, host: host},
	}
}

func (s *servedDetectorModule) Descriptor(context.Context) (*sdk.DetectorDescriptor, error) {
	descriptor := s.module.Descriptor.Clone()
	return &descriptor, nil
}

func (s *servedDetectorModule) PackageManagerSupport(ctx context.Context) ([]sdk.PackageManagerSupport, error) {
	if len(s.module.Support) > 0 {
		support := make([]sdk.PackageManagerSupport, len(s.module.Support))
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

func (s *servedDetectorModule) Ready(ctx context.Context, req *sdk.DetectRequest) (*sdk.ReadyResponse, error) {
	detector, err := s.lazy.get(ctx)
	if err != nil {
		return nil, err
	}
	return readyResponseFromError(detector.Ready(ctx, *req)), nil
}

func (s *servedDetectorModule) Applicable(ctx context.Context, req *sdk.DetectRequest) (*sdk.ApplicableResponse, error) {
	detector, err := s.lazy.get(ctx)
	if err != nil {
		return nil, err
	}
	applicable, err := detector.Applicable(ctx, *req)
	if err != nil {
		return nil, err
	}
	return &sdk.ApplicableResponse{Applicable: applicable}, nil
}

func (s *servedDetectorModule) Detect(ctx context.Context, req *sdk.DetectRequest) (*sdk.DetectResponse, error) {
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
func (s *servedDetectorModule) Install(ctx context.Context, req *sdk.DetectRequest) (*sdk.InstallResponse, error) {
	detector, err := s.lazy.get(ctx)
	if err != nil {
		return nil, err
	}
	installer, ok := detector.(sdk.InstallFirstDetector)
	if !ok {
		return &sdk.InstallResponse{}, nil
	}
	if err := installer.Install(ctx, *req); err != nil {
		return nil, err
	}
	return &sdk.InstallResponse{Performed: true}, nil
}

// servedMatcherModule adapts a MatcherModule to the ServedMatcher protocol.
type servedMatcherModule struct {
	module *sdk.MatcherModule
	lazy   *lazyComponent[sdk.Matcher]
}

func newServedMatcherModule(module *sdk.MatcherModule, host sdk.HostContext) *servedMatcherModule {
	return &servedMatcherModule{
		module: module,
		lazy:   &lazyComponent[sdk.Matcher]{newFn: module.New, host: host},
	}
}

func (s *servedMatcherModule) Descriptor(context.Context) (*sdk.MatcherDescriptor, error) {
	descriptor := s.module.Descriptor
	return &descriptor, nil
}

func (s *servedMatcherModule) Ready(ctx context.Context, req *sdk.MatchRequest) (*sdk.ReadyResponse, error) {
	matcher, err := s.lazy.get(ctx)
	if err != nil {
		return nil, err
	}
	return readyResponseFromError(matcher.Ready(ctx, *req)), nil
}

func (s *servedMatcherModule) Applicable(ctx context.Context, req *sdk.MatchRequest) (*sdk.ApplicableResponse, error) {
	matcher, err := s.lazy.get(ctx)
	if err != nil {
		return nil, err
	}
	applicable, err := matcher.Applicable(ctx, *req)
	if err != nil {
		return nil, err
	}
	return &sdk.ApplicableResponse{Applicable: applicable}, nil
}

func (s *servedMatcherModule) Match(ctx context.Context, req *sdk.MatchRequest) (*sdk.MatchResponse, error) {
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
	module *sdk.AuditorModule
	lazy   *lazyComponent[sdk.Auditor]
}

func newServedAuditorModule(module *sdk.AuditorModule, host sdk.HostContext) *servedAuditorModule {
	return &servedAuditorModule{
		module: module,
		lazy:   &lazyComponent[sdk.Auditor]{newFn: module.New, host: host},
	}
}

func (s *servedAuditorModule) Descriptor(context.Context) (*sdk.AuditorDescriptor, error) {
	descriptor := s.module.Descriptor
	return &descriptor, nil
}

func (s *servedAuditorModule) Ready(ctx context.Context, req *sdk.AuditRequest) (*sdk.ReadyResponse, error) {
	auditor, err := s.lazy.get(ctx)
	if err != nil {
		return nil, err
	}
	return readyResponseFromError(auditor.Ready(ctx, *req)), nil
}

func (s *servedAuditorModule) Applicable(ctx context.Context, req *sdk.AuditRequest) (*sdk.ApplicableResponse, error) {
	auditor, err := s.lazy.get(ctx)
	if err != nil {
		return nil, err
	}
	applicable, err := auditor.Applicable(ctx, *req)
	if err != nil {
		return nil, err
	}
	return &sdk.ApplicableResponse{Applicable: applicable}, nil
}

func (s *servedAuditorModule) Audit(ctx context.Context, req *sdk.AuditRequest) (*sdk.AuditResponse, error) {
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
	module *sdk.AnalyzerModule
	lazy   *lazyComponent[sdk.Analyzer]
}

func newServedAnalyzerModule(module *sdk.AnalyzerModule, host sdk.HostContext) *servedAnalyzerModule {
	return &servedAnalyzerModule{
		module: module,
		lazy:   &lazyComponent[sdk.Analyzer]{newFn: module.New, host: host},
	}
}

func (s *servedAnalyzerModule) Descriptor(context.Context) (*sdk.AnalyzerDescriptor, error) {
	descriptor := s.module.Descriptor
	return &descriptor, nil
}

func (s *servedAnalyzerModule) Ready(ctx context.Context, req *sdk.AnalyzeRequest) (*sdk.ReadyResponse, error) {
	analyzer, err := s.lazy.get(ctx)
	if err != nil {
		return nil, err
	}
	return readyResponseFromError(analyzer.Ready(ctx, *req)), nil
}

func (s *servedAnalyzerModule) Applicable(ctx context.Context, req *sdk.AnalyzeRequest) (*sdk.ApplicableResponse, error) {
	analyzer, err := s.lazy.get(ctx)
	if err != nil {
		return nil, err
	}
	applicable, err := analyzer.Applicable(ctx, *req)
	if err != nil {
		return nil, err
	}
	return &sdk.ApplicableResponse{Applicable: applicable}, nil
}

func (s *servedAnalyzerModule) Analyze(ctx context.Context, req *sdk.AnalyzeRequest) (*sdk.AnalyzeResponse, error) {
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
