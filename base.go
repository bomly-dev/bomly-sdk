package sdk

import "context"

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
//		sdk.BaseDetector
//	}
//
//	func (Detector) Descriptor() sdk.DetectorDescriptor { ... }
//	func (Detector) PackageManagerSupport() []sdk.PackageManagerSupport { ... }
//	func (Detector) ResolveGraph(ctx context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) { ... }
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
