// Package conformance provides a reusable test suite that plugin authors run
// against their sdk.Module to verify it satisfies the Bomly plugin contract
// before shipping: module and descriptor validity, JSON round-trip stability,
// construction through a HostContext, the Ready/Applicable lifecycle contract,
// role-specific capabilities such as the package-updates delta protocol, and
// (optionally) manifest identity and a real managed-transport probe of the
// built plugin binary.
//
// Typical usage from a plugin repository:
//
//	func TestConformance(t *testing.T) {
//		conformance.Test(t, conformance.Config{
//			Module:       plugin.Module(),
//			ManifestPath: "../bomly-plugin.json",
//		})
//	}
package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	hplugin "github.com/hashicorp/go-plugin"
	"go.uber.org/zap"

	sdk "github.com/bomly-dev/bomly-sdk"
)

// cancelledContextTimeout bounds how long a component may take to return from
// Ready/Applicable when invoked with an already-cancelled context.
const cancelledContextTimeout = 5 * time.Second

// Config configures one conformance run.
type Config struct {
	// Module is the module under test. Required.
	Module sdk.Module
	// ManifestPath optionally points at the plugin's bomly-plugin.json. When
	// set, the suite cross-checks manifest identity against the runtime
	// descriptor (id == descriptor name, kind == module kind, runtime and
	// pluginApiVersion equal the SDK constants).
	ManifestPath string
	// SampleConfig is optionally decoded into the component's configuration
	// via the stub HostContext's DecodeConfig. When empty, "{}" is decoded.
	SampleConfig json.RawMessage
}

// Test runs the conformance suite against cfg.Module as a set of subtests.
func Test(t *testing.T, cfg Config) {
	t.Helper()

	t.Run("module", func(t *testing.T) {
		if err := sdk.ValidateModule(cfg.Module); err != nil {
			t.Fatalf("ValidateModule: %v", err)
		}
	})
	if err := sdk.ValidateModule(cfg.Module); err != nil {
		// The subtest above reported the failure; the remaining checks all
		// assume a structurally valid module.
		return
	}

	t.Run("descriptor", func(t *testing.T) {
		testDescriptor(t, cfg.Module)
	})

	host := newStubHostContext(cfg.SampleConfig)
	component, err := constructComponent(context.Background(), cfg.Module, host)
	t.Run("construct", func(t *testing.T) {
		if err != nil {
			t.Fatalf("module New: %v", err)
		}
		if component == nil {
			t.Fatal("module New returned a nil component")
		}
	})
	if err != nil || component == nil {
		return
	}

	t.Run("ready-applicable", func(t *testing.T) {
		testReadyApplicable(t, cfg.Module, component)
	})

	t.Run("role", func(t *testing.T) {
		testRoleSpecific(t, cfg.Module, component)
	})

	if cfg.ManifestPath != "" {
		t.Run("manifest", func(t *testing.T) {
			testManifest(t, cfg.Module, cfg.ManifestPath)
		})
	}
}

// ProbeOption customizes a ProbeBinary run.
type ProbeOption func(*probeConfig)

type probeConfig struct {
	module *sdk.Module
}

// WithModule supplies the in-process module the probed binary is expected to
// serve. When set, ProbeBinary fetches the descriptor for the module's kind
// and asserts it equals the in-process descriptor. Without it, ProbeBinary
// only asserts that the binary serves exactly one valid role descriptor.
func WithModule(m sdk.Module) ProbeOption {
	return func(cfg *probeConfig) {
		cfg.module = &m
	}
}

// ProbeBinary starts binaryPath as a real managed plugin over the HashiCorp
// go-plugin gRPC transport (exactly as the Bomly host does), fetches the role
// descriptor over the wire, and validates it. The plugin process is killed in
// test cleanup.
func ProbeBinary(t *testing.T, binaryPath string, opts ...ProbeOption) {
	t.Helper()
	var cfg probeConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	client := hplugin.NewClient(&hplugin.ClientConfig{
		HandshakeConfig:  sdk.HandshakeConfig(),
		Plugins:          sdk.ClientPluginMap(),
		Cmd:              exec.Command(binaryPath),
		AllowedProtocols: []hplugin.Protocol{hplugin.ProtocolGRPC},
	})
	t.Cleanup(client.Kill)

	rpcClient, err := client.Client()
	if err != nil {
		t.Fatalf("start managed plugin %s: %v", binaryPath, err)
	}
	raw, err := rpcClient.Dispense("bomly")
	if err != nil {
		t.Fatalf("dispense plugin service: %v", err)
	}
	service, ok := raw.(sdk.Client)
	if !ok {
		t.Fatalf("dispensed value %T does not implement sdk.Client", raw)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if cfg.module != nil {
		probeModuleDescriptor(ctx, t, service, *cfg.module)
		return
	}
	probeAnyDescriptor(ctx, t, service)
}

// probeModuleDescriptor fetches the descriptor for the module's kind over the
// transport and asserts it equals the in-process descriptor.
func probeModuleDescriptor(ctx context.Context, t *testing.T, service sdk.Client, m sdk.Module) {
	t.Helper()
	var remote, local any
	var err error
	switch m.Kind {
	case sdk.PluginKindDetector:
		remote, err = service.DetectorDescriptor(ctx)
		local = &m.Detector.Descriptor
	case sdk.PluginKindMatcher:
		remote, err = service.MatcherDescriptor(ctx)
		local = &m.Matcher.Descriptor
	case sdk.PluginKindAuditor:
		remote, err = service.AuditorDescriptor(ctx)
		local = &m.Auditor.Descriptor
	case sdk.PluginKindAnalyzer:
		remote, err = service.AnalyzerDescriptor(ctx)
		local = &m.Analyzer.Descriptor
	default:
		t.Fatalf("module kind %q is invalid", m.Kind)
	}
	if err != nil {
		t.Fatalf("fetch %s descriptor over managed transport: %v", m.Kind, err)
	}
	// Compare canonical JSON forms so nil-vs-empty slice differences that the
	// wire encoding cannot represent do not produce false negatives.
	remoteJSON, err := json.Marshal(remote)
	if err != nil {
		t.Fatalf("marshal remote descriptor: %v", err)
	}
	localJSON, err := json.Marshal(local)
	if err != nil {
		t.Fatalf("marshal in-process descriptor: %v", err)
	}
	if string(remoteJSON) != string(localJSON) {
		t.Fatalf("descriptor served over the managed transport differs from the in-process descriptor:\nremote: %s\nlocal:  %s", remoteJSON, localJSON)
	}
}

// probeAnyDescriptor tries every role descriptor RPC and requires exactly one
// role to be implemented with a valid descriptor.
func probeAnyDescriptor(ctx context.Context, t *testing.T, service sdk.Client) {
	t.Helper()
	var served []string
	if descriptor, err := service.DetectorDescriptor(ctx); err == nil {
		if err := sdk.ValidateDetectorDescriptor(descriptor); err != nil {
			t.Errorf("served detector descriptor invalid: %v", err)
		}
		served = append(served, string(sdk.PluginKindDetector))
	}
	if descriptor, err := service.MatcherDescriptor(ctx); err == nil {
		if err := sdk.ValidateMatcherDescriptor(descriptor); err != nil {
			t.Errorf("served matcher descriptor invalid: %v", err)
		}
		served = append(served, string(sdk.PluginKindMatcher))
	}
	if descriptor, err := service.AuditorDescriptor(ctx); err == nil {
		if err := sdk.ValidateAuditorDescriptor(descriptor); err != nil {
			t.Errorf("served auditor descriptor invalid: %v", err)
		}
		served = append(served, string(sdk.PluginKindAuditor))
	}
	if descriptor, err := service.AnalyzerDescriptor(ctx); err == nil {
		if err := sdk.ValidateAnalyzerDescriptor(descriptor); err != nil {
			t.Errorf("served analyzer descriptor invalid: %v", err)
		}
		served = append(served, string(sdk.PluginKindAnalyzer))
	}
	if len(served) != 1 {
		t.Fatalf("binary must serve exactly one role descriptor, served %d (%s)", len(served), strings.Join(served, ", "))
	}
}

// --- descriptor checks -----------------------------------------------------

func testDescriptor(t *testing.T, m sdk.Module) {
	t.Helper()
	switch m.Kind {
	case sdk.PluginKindDetector:
		descriptor := m.Detector.Descriptor
		if err := sdk.ValidateDetectorDescriptor(&descriptor); err != nil {
			t.Fatalf("descriptor: %v", err)
		}
		requireRoundTrip(t, &descriptor, new(sdk.DetectorDescriptor))
	case sdk.PluginKindMatcher:
		descriptor := m.Matcher.Descriptor
		if err := sdk.ValidateMatcherDescriptor(&descriptor); err != nil {
			t.Fatalf("descriptor: %v", err)
		}
		requireRoundTrip(t, &descriptor, new(sdk.MatcherDescriptor))
	case sdk.PluginKindAuditor:
		descriptor := m.Auditor.Descriptor
		if err := sdk.ValidateAuditorDescriptor(&descriptor); err != nil {
			t.Fatalf("descriptor: %v", err)
		}
		requireRoundTrip(t, &descriptor, new(sdk.AuditorDescriptor))
	case sdk.PluginKindAnalyzer:
		descriptor := m.Analyzer.Descriptor
		if err := sdk.ValidateAnalyzerDescriptor(&descriptor); err != nil {
			t.Fatalf("descriptor: %v", err)
		}
		requireRoundTrip(t, &descriptor, new(sdk.AnalyzerDescriptor))
	}
}

// requireRoundTrip asserts marshal → unmarshal → marshal stability for a
// descriptor: the JSON form must survive a round trip through the typed struct
// unchanged, which is what the managed transport relies on.
func requireRoundTrip(t *testing.T, original, decoded any) {
	t.Helper()
	first, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal descriptor: %v", err)
	}
	if err := json.Unmarshal(first, decoded); err != nil {
		t.Fatalf("unmarshal descriptor: %v", err)
	}
	second, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("re-marshal descriptor: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("descriptor JSON round trip is not stable:\nfirst:  %s\nsecond: %s", first, second)
	}
}

// --- construction ----------------------------------------------------------

// stubHostContext is a minimal HostContext for driving components under test.
type stubHostContext struct {
	logger *zap.Logger
	http   *sdk.HTTPClientProvider
	sample json.RawMessage
}

func newStubHostContext(sample json.RawMessage) *stubHostContext {
	provider, err := sdk.NewHTTPClientProvider(sdk.HTTPClientConfig{})
	if err != nil {
		provider = nil
	}
	return &stubHostContext{logger: zap.NewNop(), http: provider, sample: sample}
}

func (s *stubHostContext) Logger() *zap.Logger                 { return s.logger }
func (s *stubHostContext) HTTPClient() *sdk.HTTPClientProvider { return s.http }
func (s *stubHostContext) Runtime() sdk.RuntimeInfo {
	return sdk.RuntimeInfo{Execution: sdk.ExecutionEmbedded}
}

func (s *stubHostContext) DecodeConfig(v any) error {
	payload := s.sample
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	if err := json.Unmarshal(payload, v); err != nil {
		return fmt.Errorf("decode sample config: %w", err)
	}
	return nil
}

// constructComponent builds the module's component through its constructor and
// returns it as the role interface value.
func constructComponent(ctx context.Context, m sdk.Module, host sdk.HostContext) (any, error) {
	switch m.Kind {
	case sdk.PluginKindDetector:
		component, err := m.Detector.New(ctx, host)
		return normalizeNil(component), err
	case sdk.PluginKindMatcher:
		component, err := m.Matcher.New(ctx, host)
		return normalizeNil(component), err
	case sdk.PluginKindAuditor:
		component, err := m.Auditor.New(ctx, host)
		return normalizeNil(component), err
	case sdk.PluginKindAnalyzer:
		component, err := m.Analyzer.New(ctx, host)
		return normalizeNil(component), err
	}
	return nil, fmt.Errorf("module kind %q is invalid", m.Kind)
}

// normalizeNil maps typed-nil interface values to untyped nil so callers can
// use a plain == nil check.
func normalizeNil(v any) any {
	if v == nil {
		return nil
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		if rv.IsNil() {
			return nil
		}
	}
	return v
}

// --- Ready / Applicable contract -------------------------------------------

func testReadyApplicable(t *testing.T, m sdk.Module, component any) {
	t.Helper()

	// Zero-value request with a live context: neither call may panic. Errors
	// are legal (Ready returning an error means "not ready").
	callGuarded(t, "Ready(zero request)", func(ctx context.Context) {
		_ = callReady(ctx, m, component)
	})
	callGuarded(t, "Applicable(zero request)", func(ctx context.Context) {
		_, _ = callApplicable(ctx, m, component)
	})

	// Already-cancelled context: calls must return promptly instead of
	// blocking on I/O that ignores cancellation.
	requirePromptReturn(t, "Ready", func(ctx context.Context) {
		_ = callReady(ctx, m, component)
	})
	requirePromptReturn(t, "Applicable", func(ctx context.Context) {
		_, _ = callApplicable(ctx, m, component)
	})
}

func callReady(ctx context.Context, m sdk.Module, component any) error {
	switch m.Kind {
	case sdk.PluginKindDetector:
		return component.(sdk.Detector).Ready(ctx, sdk.DetectionRequest{})
	case sdk.PluginKindMatcher:
		return component.(sdk.Matcher).Ready(ctx, sdk.MatchRequest{})
	case sdk.PluginKindAuditor:
		return component.(sdk.Auditor).Ready(ctx, sdk.AuditRequest{})
	case sdk.PluginKindAnalyzer:
		return component.(sdk.Analyzer).Ready(ctx, sdk.AnalyzeRequest{})
	}
	return fmt.Errorf("module kind %q is invalid", m.Kind)
}

func callApplicable(ctx context.Context, m sdk.Module, component any) (bool, error) {
	switch m.Kind {
	case sdk.PluginKindDetector:
		return component.(sdk.Detector).Applicable(ctx, sdk.DetectionRequest{})
	case sdk.PluginKindMatcher:
		return component.(sdk.Matcher).Applicable(ctx, sdk.MatchRequest{})
	case sdk.PluginKindAuditor:
		return component.(sdk.Auditor).Applicable(ctx, sdk.AuditRequest{})
	case sdk.PluginKindAnalyzer:
		return component.(sdk.Analyzer).Applicable(ctx, sdk.AnalyzeRequest{})
	}
	return false, fmt.Errorf("module kind %q is invalid", m.Kind)
}

// callGuarded invokes fn with a live context and converts a panic into a test
// failure with a readable label.
func callGuarded(t *testing.T, label string, fn func(context.Context)) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s panicked: %v", label, r)
		}
	}()
	fn(context.Background())
}

// requirePromptReturn invokes fn with an already-cancelled context and fails
// if it does not return within cancelledContextTimeout.
func requirePromptReturn(t *testing.T, label string, fn func(context.Context)) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("%s panicked with cancelled context: %v", label, r)
			}
		}()
		fn(ctx)
	}()
	select {
	case <-done:
	case <-time.After(cancelledContextTimeout):
		t.Errorf("%s did not return within %s after context cancellation", label, cancelledContextTimeout)
	}
}

// --- role-specific checks --------------------------------------------------

func testRoleSpecific(t *testing.T, m sdk.Module, component any) {
	t.Helper()
	switch m.Kind {
	case sdk.PluginKindDetector:
		testDetectorSupport(t, m, component.(sdk.Detector))
	case sdk.PluginKindMatcher:
		matcher := component.(sdk.Matcher)
		if hasCapability(m.Matcher.Descriptor.Capabilities, sdk.CapabilityPackageUpdates) {
			testMatcherPackageUpdates(t, matcher)
		}
	case sdk.PluginKindAnalyzer:
		analyzer := component.(sdk.Analyzer)
		if hasCapability(m.Analyzer.Descriptor.Capabilities, sdk.CapabilityPackageUpdates) {
			testAnalyzerPackageUpdates(t, analyzer)
		}
	}
}

func hasCapability(capabilities []string, capability string) bool {
	for _, entry := range capabilities {
		if entry == capability {
			return true
		}
	}
	return false
}

// testDetectorSupport requires discoverable package-manager support: without
// names and evidence patterns Bomly cannot include the detector in subproject
// discovery or scan planning.
func testDetectorSupport(t *testing.T, m sdk.Module, detector sdk.Detector) {
	t.Helper()
	support := m.Detector.Support
	if len(support) == 0 {
		support = detector.PackageManagerSupport()
	}
	if len(support) == 0 {
		t.Fatal("detector declares no package-manager support (module Support and component PackageManagerSupport are both empty)")
	}
	for idx, entry := range support {
		if strings.TrimSpace(entry.PackageManager.Name()) == "" {
			t.Errorf("package-manager support entry %d has an empty package manager name", idx)
		}
		if len(entry.EvidencePatterns) == 0 {
			t.Errorf("package-manager support entry %d (%s) has no evidence patterns; discovery cannot plan the detector without them", idx, entry.PackageManager.Name())
		}
	}

	// Declared target kinds (when any) must be non-empty values; an empty list
	// is fine and means the host derives the default kinds.
	for idx, kind := range m.Detector.TargetKinds {
		if strings.TrimSpace(string(kind)) == "" {
			t.Errorf("target kind entry %d is empty; omit the entry or declare a concrete execution target kind", idx)
		}
	}
}

// testMatcherPackageUpdates drives Match with AcceptPackageUpdates=true on an
// empty registry and verifies any returned deltas merge cleanly.
func testMatcherPackageUpdates(t *testing.T, matcher sdk.Matcher) {
	t.Helper()
	ctx := context.Background()
	req := sdk.MatchRequest{
		Registry:             sdk.NewPackageRegistry(),
		AcceptPackageUpdates: true,
	}
	if err := matcher.Ready(ctx, req); err != nil {
		t.Skipf("matcher not ready in this environment, skipping package-updates check: %v", err)
	}
	result, err := matcher.Match(ctx, req)
	if err != nil {
		t.Fatalf("Match with AcceptPackageUpdates on an empty registry: %v", err)
	}
	verifyPackageUpdatesMerge(t, result.PackageUpdates)
}

// testAnalyzerPackageUpdates is the analyzer variant of the delta check.
func testAnalyzerPackageUpdates(t *testing.T, analyzer sdk.Analyzer) {
	t.Helper()
	ctx := context.Background()
	req := sdk.AnalyzeRequest{
		Registry:             sdk.NewPackageRegistry(),
		AcceptPackageUpdates: true,
	}
	if err := analyzer.Ready(ctx, req); err != nil {
		t.Skipf("analyzer not ready in this environment, skipping package-updates check: %v", err)
	}
	result, err := analyzer.Analyze(ctx, req)
	if err != nil {
		t.Fatalf("Analyze with AcceptPackageUpdates on an empty registry: %v", err)
	}
	verifyPackageUpdatesMerge(t, result.PackageUpdates)
}

// verifyPackageUpdatesMerge asserts every returned delta carries a PURL and
// merges into a registry via the host's standard merge path.
func verifyPackageUpdatesMerge(t *testing.T, updates []*sdk.Package) {
	t.Helper()
	for idx, update := range updates {
		if update == nil {
			t.Errorf("package update %d is nil", idx)
			continue
		}
		if update.PURL == "" {
			t.Errorf("package update %d has no PURL; the host merges deltas by PURL and would drop it", idx)
		}
	}
	registry := sdk.ApplyPackageUpdates(sdk.NewPackageRegistry(), updates)
	if registry == nil {
		t.Fatal("ApplyPackageUpdates returned a nil registry")
	}
}

// --- manifest cross-check --------------------------------------------------

// manifestIdentity is the minimal slice of bomly-plugin.json the suite needs
// to verify identity agreement with the runtime descriptor.
type manifestIdentity struct {
	SchemaVersion    string            `json:"schemaVersion"`
	ID               string            `json:"id"`
	Kind             string            `json:"kind"`
	Runtime          string            `json:"runtime"`
	PluginAPIVersion string            `json:"pluginApiVersion"`
	Entrypoint       map[string]string `json:"entrypoint"`
}

func testManifest(t *testing.T, m sdk.Module, manifestPath string) {
	t.Helper()
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest manifestIdentity
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse manifest %s: %v", manifestPath, err)
	}

	name := descriptorName(m)
	if manifest.ID != name {
		t.Errorf("manifest id %q must equal the runtime descriptor name %q", manifest.ID, name)
	}
	if manifest.Kind != string(m.Kind) {
		t.Errorf("manifest kind %q must equal the module kind %q", manifest.Kind, m.Kind)
	}
	if manifest.Runtime != sdk.RuntimeHashiCorpGRPC {
		t.Errorf("manifest runtime %q must equal %q", manifest.Runtime, sdk.RuntimeHashiCorpGRPC)
	}
	if manifest.PluginAPIVersion != sdk.PluginAPIVersion {
		t.Errorf("manifest pluginApiVersion %q must equal %q", manifest.PluginAPIVersion, sdk.PluginAPIVersion)
	}
	if manifest.SchemaVersion != sdk.PackageManifestSchemaVersion {
		t.Errorf("manifest schemaVersion %q must equal %q", manifest.SchemaVersion, sdk.PackageManifestSchemaVersion)
	}
	if len(manifest.Entrypoint) == 0 {
		t.Error("manifest entrypoint map must declare at least one GOOS/GOARCH binary")
	}
}

// descriptorName returns the runtime descriptor name for the module's role.
func descriptorName(m sdk.Module) string {
	switch m.Kind {
	case sdk.PluginKindDetector:
		return m.Detector.Descriptor.Name
	case sdk.PluginKindMatcher:
		return m.Matcher.Descriptor.Name
	case sdk.PluginKindAuditor:
		return m.Auditor.Descriptor.Name
	case sdk.PluginKindAnalyzer:
		return m.Analyzer.Descriptor.Name
	}
	return ""
}
