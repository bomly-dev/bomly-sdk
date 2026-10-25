package plugin

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/httpkit"
	"github.com/bomly-dev/bomly-sdk/model"
)

func detectorModuleFixture() *DetectorModule {
	return &DetectorModule{
		Descriptor: DetectorDescriptor{Name: "fake-detector"},
		Support:    []PackageManagerSupport{Support(model.PackageManagerNPM, "package-lock.json")},
		New: func(context.Context, HostContext) (Detector, error) {
			return minimalDetector{}, nil
		},
	}
}

func TestValidateModule(t *testing.T) {
	matcherModule := &MatcherModule{
		Descriptor: MatcherDescriptor{Name: "fake-matcher"},
		New: func(context.Context, HostContext) (Matcher, error) {
			return nil, errors.New("unused")
		},
	}
	auditorModule := &AuditorModule{
		Descriptor: AuditorDescriptor{Name: "fake-auditor"},
		New: func(context.Context, HostContext) (Auditor, error) {
			return nil, errors.New("unused")
		},
	}
	analyzerModule := &AnalyzerModule{
		Descriptor: AnalyzerDescriptor{Name: "fake-analyzer"},
		New: func(context.Context, HostContext) (Analyzer, error) {
			return nil, errors.New("unused")
		},
	}

	cases := []struct {
		name    string
		module  Module
		wantErr string
	}{
		{
			name:   "valid detector",
			module: Module{Kind: PluginKindDetector, Detector: detectorModuleFixture()},
		},
		{
			name:   "valid matcher",
			module: Module{Kind: PluginKindMatcher, Matcher: matcherModule},
		},
		{
			name:   "valid auditor",
			module: Module{Kind: PluginKindAuditor, Auditor: auditorModule},
		},
		{
			name:   "valid analyzer",
			module: Module{Kind: PluginKindAnalyzer, Analyzer: analyzerModule},
		},
		{
			name:    "no role",
			module:  Module{Kind: PluginKindDetector},
			wantErr: "exactly one role",
		},
		{
			name: "two roles",
			module: Module{
				Kind:     PluginKindDetector,
				Detector: detectorModuleFixture(),
				Matcher:  matcherModule,
			},
			wantErr: "exactly one role",
		},
		{
			name:    "kind role mismatch",
			module:  Module{Kind: PluginKindMatcher, Detector: detectorModuleFixture()},
			wantErr: "requires the Matcher role",
		},
		{
			name:    "invalid kind",
			module:  Module{Kind: PluginKind("bogus"), Detector: detectorModuleFixture()},
			wantErr: "is invalid",
		},
		{
			name: "valid detector with target kinds",
			module: Module{Kind: PluginKindDetector, Detector: func() *DetectorModule {
				module := detectorModuleFixture()
				module.TargetKinds = []ExecutionTargetKind{ExecutionTargetFilesystem, ExecutionTargetGitRepository}
				return module
			}()},
		},
		{
			name: "empty target kind",
			module: Module{Kind: PluginKindDetector, Detector: func() *DetectorModule {
				module := detectorModuleFixture()
				module.TargetKinds = []ExecutionTargetKind{ExecutionTargetFilesystem, ""}
				return module
			}()},
			wantErr: "target kinds must not contain empty values",
		},
		{
			name: "missing constructor",
			module: Module{Kind: PluginKindDetector, Detector: &DetectorModule{
				Descriptor: DetectorDescriptor{Name: "fake"},
			}},
			wantErr: "constructor is required",
		},
		{
			name: "invalid descriptor",
			module: Module{Kind: PluginKindAnalyzer, Analyzer: &AnalyzerModule{
				Descriptor: AnalyzerDescriptor{Name: "   "},
				New: func(context.Context, HostContext) (Analyzer, error) {
					return nil, errors.New("unused")
				},
			}},
			wantErr: "descriptor",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateModule(tc.module)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid module, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestComponentScopeRunsCleanupsLIFOOnce pins the ordering and at-most-once
// rules: the last resource acquired is the first released, and a second
// Close runs nothing and reports what the first one did.
func TestComponentScopeRunsCleanupsLIFOOnce(t *testing.T) {
	scope := NewComponentScope(context.Background(), "matcher-x")
	var order []string
	for _, name := range []string{"file", "tempdir", "transport"} {
		scope.OnCleanup(func() error {
			order = append(order, name)
			return nil
		})
	}
	scope.OnCleanup(nil)
	if err := scope.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if want := []string{"transport", "tempdir", "file"}; !slices.Equal(order, want) {
		t.Errorf("cleanup order = %v, want %v", order, want)
	}
	if err := scope.Close(); err != nil || len(order) != 3 {
		t.Errorf("second Close ran cleanups again or failed: order %v, err %v", order, err)
	}
}

// TestComponentScopeAttemptsEveryCleanup holds the error contract: a failing
// or panicking cleanup does not stop the ones registered before it, every
// failure is reported, each names the component, and a repeated Close
// returns the same joined error.
func TestComponentScopeAttemptsEveryCleanup(t *testing.T) {
	scope := NewComponentScope(context.Background(), "analyzer-y")
	errClose := errors.New("close socket")
	ran := 0
	scope.OnCleanup(func() error { ran++; return nil })
	scope.OnCleanup(func() error { ran++; return errClose })
	scope.OnCleanup(func() error { ran++; panic("boom") })

	err := scope.Close()
	if ran != 3 {
		t.Fatalf("%d of 3 cleanups ran", ran)
	}
	if !errors.Is(err, errClose) {
		t.Errorf("joined error %v does not wrap the cleanup's error", err)
	}
	for _, want := range []string{"analyzer-y: cleanup: close socket", "analyzer-y: cleanup: panic: boom"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("joined error %v lacks %q", err, want)
		}
	}
	if again := scope.Close(); again != err {
		t.Errorf("second Close = %v, want the first Close's %v", again, err)
	}
}

// TestComponentScopeSecondCloseWaitsForTheFirst: a Close that arrives while
// the first is still running cleanups must not report success early.
func TestComponentScopeSecondCloseWaitsForTheFirst(t *testing.T) {
	scope := NewComponentScope(context.Background(), "slow-cleanup")
	release := make(chan struct{})
	started := make(chan struct{})
	errSlow := errors.New("slow failed")
	scope.OnCleanup(func() error {
		close(started)
		<-release
		return errSlow
	})
	go func() { _ = scope.Close() }()
	<-started
	second := make(chan error, 1)
	go func() { second <- scope.Close() }()
	select {
	case err := <-second:
		t.Fatalf("second Close returned %v while the first was still running cleanups", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-second; !errors.Is(err, errSlow) {
		t.Errorf("second Close = %v, want the first Close's error", err)
	}
}

// TestComponentScopeContextEndsWithTheLifetime: the constructor's context is
// cancelled by Close -- before the cleanups run, so a goroutine watching it
// stops before its resources go -- and by the parent, which runs nothing.
func TestComponentScopeContextEndsWithTheLifetime(t *testing.T) {
	scope := NewComponentScope(context.Background(), "detector-z")
	var cancelledFirst bool
	scope.OnCleanup(func() error {
		cancelledFirst = scope.Context().Err() != nil
		return nil
	})
	if scope.Context().Err() != nil {
		t.Fatal("a fresh scope's context is already cancelled")
	}
	if err := scope.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !cancelledFirst {
		t.Error("cleanups ran before the lifetime context was cancelled")
	}

	parent, cancel := context.WithCancel(context.Background())
	child := NewComponentScope(parent, "child")
	ran := false
	child.OnCleanup(func() error { ran = true; return nil })
	cancel()
	if child.Context().Err() == nil {
		t.Error("cancelling the parent did not cancel the scope")
	}
	if ran {
		t.Error("cancelling the parent ran a cleanup; only Close may")
	}
	_ = child.Close()
	if !ran {
		t.Error("Close after the parent was cancelled did not run the cleanup")
	}
}

// TestComponentScopeLateRegistrationRunsAtOnce covers a constructor that
// never finished before its lifetime ended: what it acquires afterwards is
// released immediately rather than leaked.
func TestComponentScopeLateRegistrationRunsAtOnce(t *testing.T) {
	scope := NewComponentScope(context.Background(), "slow")
	if err := scope.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ran := false
	scope.OnCleanup(func() error {
		ran = true
		if scope.Context().Err() == nil {
			t.Error("a late cleanup ran before the lifetime context was cancelled")
		}
		return errors.New("dropped")
	})
	if !ran {
		t.Error("a cleanup registered after Close did not run")
	}
}

// TestComponentScopeReleasesAfterFailedConstruction is the case a
// constructor most often gets wrong: it acquires, registers, then fails.
// The host closes the scope regardless, and the resource is released.
func TestComponentScopeReleasesAfterFailedConstruction(t *testing.T) {
	scope := NewComponentScope(context.Background(), "matcher-x")
	host := scopedHost{scope: scope}
	released := false
	module := MatcherModule{New: func(_ context.Context, host HostContext) (Matcher, error) {
		host.OnCleanup(func() error { released = true; return nil })
		return nil, errors.New("config invalid")
	}}
	if _, err := module.New(scope.Context(), host); err == nil {
		t.Fatal("constructor unexpectedly succeeded")
	}
	if err := scope.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !released {
		t.Error("a resource registered before the constructor failed was not released")
	}
}

// TestComponentScopeConcurrentClose runs registration and Close from many
// goroutines; under -race it proves the scope is safe to share, and every
// registered cleanup runs exactly once whichever side won.
func TestComponentScopeConcurrentClose(t *testing.T) {
	scope := NewComponentScope(context.Background(), "shared")
	var mu sync.Mutex
	runs := 0
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			scope.OnCleanup(func() error {
				mu.Lock()
				runs++
				mu.Unlock()
				return nil
			})
		})
		wg.Go(func() { _ = scope.Close() })
	}
	wg.Wait()
	_ = scope.Close()
	if runs != 32 {
		t.Errorf("%d of 32 cleanups ran", runs)
	}
}

// scopedHost is a HostContext whose lifetime is a ComponentScope.
type scopedHost struct {
	scope *ComponentScope
}

func (scopedHost) Logger() *zap.Logger                 { return zap.NewNop() }
func (scopedHost) HTTPClient() *httpkit.ClientProvider { return nil }
func (scopedHost) Runtime() RuntimeInfo                { return RuntimeInfo{Execution: ExecutionEmbedded} }
func (scopedHost) DecodeConfig(any) error              { return nil }
func (h scopedHost) OnCleanup(fn func() error)         { h.scope.OnCleanup(fn) }
