package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	hplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	sdk "github.com/bomly-dev/bomly-sdk"
)

const pluginName = "bomly"

// ServedDetector is the detector interface implemented by external detector
// plugins. A detector describes its identity and package-manager support,
// reports readiness/applicability for a planned scan target, and returns one or
// more manifest-scoped dependency graphs from Detect.
type ServedDetector interface {
	Descriptor(context.Context) (*sdk.DetectorDescriptor, error)
	PackageManagerSupport(context.Context) ([]sdk.PackageManagerSupport, error)
	Ready(context.Context, *sdk.DetectRequest) (*sdk.ReadyResponse, error)
	Applicable(context.Context, *sdk.DetectRequest) (*sdk.ApplicableResponse, error)
	Detect(context.Context, *sdk.DetectRequest) (*sdk.DetectResponse, error)
}

// DetectorInstaller optionally performs install-first preparation before
// detection. Implement this only for detectors that need to prepare project
// dependencies before reading them; Bomly calls it only when install-first
// execution is requested.
type DetectorInstaller interface {
	Install(context.Context, *sdk.DetectRequest) (*sdk.InstallResponse, error)
}

// ServedDetectorRemediationProvider optionally supplies read-only,
// package-manager-specific remediation evidence.
type ServedDetectorRemediationProvider interface {
	RemediationHints(context.Context, *sdk.RemediationHintRequest) (*sdk.RemediationHintResponse, error)
}

// ServedMatcher is the matcher interface implemented by external matcher
// plugins. Matchers read the dependency graph and PURL-keyed package registry,
// then return the registry with package enrichment such as licenses,
// vulnerabilities, lifecycle data, or other metadata.
type ServedMatcher interface {
	Descriptor(context.Context) (*sdk.MatcherDescriptor, error)
	Ready(context.Context, *sdk.MatchRequest) (*sdk.ReadyResponse, error)
	Applicable(context.Context, *sdk.MatchRequest) (*sdk.ApplicableResponse, error)
	Match(context.Context, *sdk.MatchRequest) (*sdk.MatchResponse, error)
}

// ServedAuditor is the auditor interface implemented by external auditor
// plugins. Auditors read graph and registry data and return reference-style
// findings, risk scores, and run metadata.
type ServedAuditor interface {
	Descriptor(context.Context) (*sdk.AuditorDescriptor, error)
	Ready(context.Context, *sdk.AuditRequest) (*sdk.ReadyResponse, error)
	Applicable(context.Context, *sdk.AuditRequest) (*sdk.ApplicableResponse, error)
	Audit(context.Context, *sdk.AuditRequest) (*sdk.AuditResponse, error)
}

// Client is the generic runtime client used by Bomly core.
type Client interface {
	DetectorDescriptor(context.Context) (*sdk.DetectorDescriptor, error)
	DetectorPackageManagerSupport(context.Context) ([]sdk.PackageManagerSupport, error)
	DetectorReady(context.Context, *sdk.DetectRequest) (*sdk.ReadyResponse, error)
	DetectorApplicable(context.Context, *sdk.DetectRequest) (*sdk.ApplicableResponse, error)
	DetectorInstall(context.Context, *sdk.DetectRequest) (*sdk.InstallResponse, error)
	Detect(context.Context, *sdk.DetectRequest) (*sdk.DetectResponse, error)
	DetectorRemediationHints(context.Context, *sdk.RemediationHintRequest) (*sdk.RemediationHintResponse, error)
	MatcherDescriptor(context.Context) (*sdk.MatcherDescriptor, error)
	MatcherReady(context.Context, *sdk.MatchRequest) (*sdk.ReadyResponse, error)
	MatcherApplicable(context.Context, *sdk.MatchRequest) (*sdk.ApplicableResponse, error)
	Match(context.Context, *sdk.MatchRequest) (*sdk.MatchResponse, error)
	AuditorDescriptor(context.Context) (*sdk.AuditorDescriptor, error)
	AuditorReady(context.Context, *sdk.AuditRequest) (*sdk.ReadyResponse, error)
	AuditorApplicable(context.Context, *sdk.AuditRequest) (*sdk.ApplicableResponse, error)
	Audit(context.Context, *sdk.AuditRequest) (*sdk.AuditResponse, error)
	AnalyzerDescriptor(context.Context) (*sdk.AnalyzerDescriptor, error)
	AnalyzerReady(context.Context, *sdk.AnalyzeRequest) (*sdk.ReadyResponse, error)
	AnalyzerApplicable(context.Context, *sdk.AnalyzeRequest) (*sdk.ApplicableResponse, error)
	Analyze(context.Context, *sdk.AnalyzeRequest) (*sdk.AnalyzeResponse, error)
}

// HandshakeConfig returns the shared HashiCorp go-plugin handshake configuration.
func HandshakeConfig() hplugin.HandshakeConfig {
	return hplugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "BOMLY_PLUGIN_RUNTIME",
		MagicCookieValue: "bomly-managed-plugin",
	}
}

// ClientPluginMap returns the client-side plugin map used by Bomly core.
func ClientPluginMap() map[string]hplugin.Plugin {
	return map[string]hplugin.Plugin{
		pluginName: &managedPlugin{},
	}
}

// ServeDetector serves one detector plugin over Bomly's managed HashiCorp
// go-plugin gRPC transport. Call it from the plugin binary's main function.
func ServeDetector(detector ServedDetector) {
	serve(detector, nil, nil, nil)
}

// ServeMatcher serves one matcher plugin over Bomly's managed HashiCorp
// go-plugin gRPC transport. Call it from the plugin binary's main function.
func ServeMatcher(matcher ServedMatcher) {
	serve(nil, matcher, nil, nil)
}

// ServeAuditor serves one auditor plugin over Bomly's managed HashiCorp
// go-plugin gRPC transport. Call it from the plugin binary's main function.
func ServeAuditor(auditor ServedAuditor) {
	serve(nil, nil, auditor, nil)
}

func serve(detector ServedDetector, matcher ServedMatcher, auditor ServedAuditor, analyzer ServedAnalyzer) {
	hplugin.Serve(&hplugin.ServeConfig{
		HandshakeConfig: HandshakeConfig(),
		Plugins: map[string]hplugin.Plugin{
			pluginName: &managedPlugin{
				server: &serviceServer{
					detector: detector,
					matcher:  matcher,
					auditor:  auditor,
					analyzer: analyzer,
				},
			},
		},
		GRPCServer: hplugin.DefaultGRPCServer,
	})
}

type managedPlugin struct {
	hplugin.NetRPCUnsupportedPlugin
	server *serviceServer
}

func (p *managedPlugin) GRPCServer(_ *hplugin.GRPCBroker, server *grpc.Server) error {
	registerPluginService(server, p.server)
	return nil
}

func (p *managedPlugin) GRPCClient(_ context.Context, _ *hplugin.GRPCBroker, conn *grpc.ClientConn) (any, error) {
	return &serviceClient{conn: conn}, nil
}

type serviceServer struct {
	detector ServedDetector
	matcher  ServedMatcher
	auditor  ServedAuditor
	analyzer ServedAnalyzer
}

type pluginServiceServer interface {
	DetectorDescriptor(context.Context, *emptypb.Empty) (*wrapperspb.BytesValue, error)
	DetectorPackageManagerSupport(context.Context, *emptypb.Empty) (*wrapperspb.BytesValue, error)
	DetectorReady(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	DetectorApplicable(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	DetectorInstall(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	Detect(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	DetectorRemediationHints(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	MatcherDescriptor(context.Context, *emptypb.Empty) (*wrapperspb.BytesValue, error)
	MatcherReady(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	MatcherApplicable(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	Match(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	AuditorDescriptor(context.Context, *emptypb.Empty) (*wrapperspb.BytesValue, error)
	AuditorReady(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	AuditorApplicable(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	Audit(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	AnalyzerDescriptor(context.Context, *emptypb.Empty) (*wrapperspb.BytesValue, error)
	AnalyzerReady(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	AnalyzerApplicable(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	Analyze(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
}

func (s *serviceServer) DetectorDescriptor(ctx context.Context, _ *emptypb.Empty) (*wrapperspb.BytesValue, error) {
	if s.detector == nil {
		return nil, status.Error(codes.Unimplemented, "detector not implemented")
	}
	descriptor, err := s.detector.Descriptor(ctx)
	if err != nil {
		return nil, err
	}
	if err := sdk.ValidateDetectorDescriptor(descriptor); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid detector descriptor: %v", err)
	}
	data, err := json.Marshal(descriptor)
	if err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}
	return wrapperspb.Bytes(data), nil
}

func (s *serviceServer) DetectorPackageManagerSupport(ctx context.Context, _ *emptypb.Empty) (*wrapperspb.BytesValue, error) {
	if s.detector == nil {
		return nil, status.Error(codes.Unimplemented, "detector not implemented")
	}
	support, err := s.detector.PackageManagerSupport(ctx)
	if err != nil {
		return nil, err
	}
	for _, entry := range support {
		if strings.TrimSpace(entry.PackageManager.Name()) == "" {
			return nil, status.Error(codes.InvalidArgument, "detector package manager support must not contain empty package manager values")
		}
	}
	data, err := json.Marshal(support)
	if err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}
	return wrapperspb.Bytes(data), nil
}

func (s *serviceServer) Detect(ctx context.Context, in *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	if s.detector == nil {
		return nil, status.Error(codes.Unimplemented, "detector not implemented")
	}
	req, err := unmarshalPayload[sdk.DetectRequest](in)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decode detect request: %v", err)
	}
	return marshalResponse(ctx, func(ctx context.Context) (*sdk.DetectResponse, error) {
		return s.detector.Detect(ctx, req)
	})
}

func (s *serviceServer) DetectorReady(ctx context.Context, in *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	if s.detector == nil {
		return nil, status.Error(codes.Unimplemented, "detector not implemented")
	}
	req, err := unmarshalPayload[sdk.DetectRequest](in)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decode detector ready request: %v", err)
	}
	return marshalResponse(ctx, func(ctx context.Context) (*sdk.ReadyResponse, error) {
		return s.detector.Ready(ctx, req)
	})
}

func (s *serviceServer) DetectorApplicable(ctx context.Context, in *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	if s.detector == nil {
		return nil, status.Error(codes.Unimplemented, "detector not implemented")
	}
	req, err := unmarshalPayload[sdk.DetectRequest](in)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decode detector applicable request: %v", err)
	}
	return marshalResponse(ctx, func(ctx context.Context) (*sdk.ApplicableResponse, error) {
		return s.detector.Applicable(ctx, req)
	})
}

func (s *serviceServer) DetectorInstall(ctx context.Context, in *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	if s.detector == nil {
		return nil, status.Error(codes.Unimplemented, "detector not implemented")
	}
	req, err := unmarshalPayload[sdk.DetectRequest](in)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decode detector install request: %v", err)
	}
	return marshalResponse(ctx, func(ctx context.Context) (*sdk.InstallResponse, error) {
		if detector, ok := s.detector.(DetectorInstaller); ok {
			return detector.Install(ctx, req)
		}
		return &sdk.InstallResponse{}, nil
	})
}

func (s *serviceServer) DetectorRemediationHints(ctx context.Context, in *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	if s.detector == nil {
		return nil, status.Error(codes.Unimplemented, "detector not implemented")
	}
	provider, ok := s.detector.(ServedDetectorRemediationProvider)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "detector remediation hints not implemented")
	}
	req, err := unmarshalPayload[sdk.RemediationHintRequest](in)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decode detector remediation hint request: %v", err)
	}
	return marshalResponse(ctx, func(ctx context.Context) (*sdk.RemediationHintResponse, error) {
		return provider.RemediationHints(ctx, req)
	})
}

func (s *serviceServer) Match(ctx context.Context, in *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	if s.matcher == nil {
		return nil, status.Error(codes.Unimplemented, "matcher not implemented")
	}
	req, err := unmarshalPayload[sdk.MatchRequest](in)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decode match request: %v", err)
	}
	return marshalResponse(ctx, func(ctx context.Context) (*sdk.MatchResponse, error) {
		return s.matcher.Match(ctx, req)
	})
}

func (s *serviceServer) MatcherDescriptor(ctx context.Context, _ *emptypb.Empty) (*wrapperspb.BytesValue, error) {
	if s.matcher == nil {
		return nil, status.Error(codes.Unimplemented, "matcher not implemented")
	}
	descriptor, err := s.matcher.Descriptor(ctx)
	if err != nil {
		return nil, err
	}
	if err := sdk.ValidateMatcherDescriptor(descriptor); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid matcher descriptor: %v", err)
	}
	data, err := json.Marshal(descriptor)
	if err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}
	return wrapperspb.Bytes(data), nil
}

func (s *serviceServer) MatcherReady(ctx context.Context, in *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	if s.matcher == nil {
		return nil, status.Error(codes.Unimplemented, "matcher not implemented")
	}
	req, err := unmarshalPayload[sdk.MatchRequest](in)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decode matcher ready request: %v", err)
	}
	return marshalResponse(ctx, func(ctx context.Context) (*sdk.ReadyResponse, error) {
		return s.matcher.Ready(ctx, req)
	})
}

func (s *serviceServer) MatcherApplicable(ctx context.Context, in *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	if s.matcher == nil {
		return nil, status.Error(codes.Unimplemented, "matcher not implemented")
	}
	req, err := unmarshalPayload[sdk.MatchRequest](in)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decode matcher applicable request: %v", err)
	}
	return marshalResponse(ctx, func(ctx context.Context) (*sdk.ApplicableResponse, error) {
		return s.matcher.Applicable(ctx, req)
	})
}

func (s *serviceServer) Audit(ctx context.Context, in *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	if s.auditor == nil {
		return nil, status.Error(codes.Unimplemented, "auditor not implemented")
	}
	req, err := unmarshalPayload[sdk.AuditRequest](in)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decode audit request: %v", err)
	}
	return marshalResponse(ctx, func(ctx context.Context) (*sdk.AuditResponse, error) {
		return s.auditor.Audit(ctx, req)
	})
}

func (s *serviceServer) AuditorDescriptor(ctx context.Context, _ *emptypb.Empty) (*wrapperspb.BytesValue, error) {
	if s.auditor == nil {
		return nil, status.Error(codes.Unimplemented, "auditor not implemented")
	}
	descriptor, err := s.auditor.Descriptor(ctx)
	if err != nil {
		return nil, err
	}
	if err := sdk.ValidateAuditorDescriptor(descriptor); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid auditor descriptor: %v", err)
	}
	data, err := json.Marshal(descriptor)
	if err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}
	return wrapperspb.Bytes(data), nil
}

func (s *serviceServer) AuditorReady(ctx context.Context, in *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	if s.auditor == nil {
		return nil, status.Error(codes.Unimplemented, "auditor not implemented")
	}
	req, err := unmarshalPayload[sdk.AuditRequest](in)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decode auditor ready request: %v", err)
	}
	return marshalResponse(ctx, func(ctx context.Context) (*sdk.ReadyResponse, error) {
		return s.auditor.Ready(ctx, req)
	})
}

func (s *serviceServer) AuditorApplicable(ctx context.Context, in *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	if s.auditor == nil {
		return nil, status.Error(codes.Unimplemented, "auditor not implemented")
	}
	req, err := unmarshalPayload[sdk.AuditRequest](in)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decode auditor applicable request: %v", err)
	}
	return marshalResponse(ctx, func(ctx context.Context) (*sdk.ApplicableResponse, error) {
		return s.auditor.Applicable(ctx, req)
	})
}

type serviceClient struct {
	conn grpc.ClientConnInterface
}

func (c *serviceClient) DetectorDescriptor(ctx context.Context) (*sdk.DetectorDescriptor, error) {
	out := new(wrapperspb.BytesValue)
	if err := c.conn.Invoke(ctx, "/bomly.plugin.v1.Plugin/DetectorDescriptor", &emptypb.Empty{}, out); err != nil {
		return nil, err
	}
	return unmarshalBytes[sdk.DetectorDescriptor](out.Value)
}

func (c *serviceClient) DetectorPackageManagerSupport(ctx context.Context) ([]sdk.PackageManagerSupport, error) {
	out := new(wrapperspb.BytesValue)
	if err := c.conn.Invoke(ctx, "/bomly.plugin.v1.Plugin/DetectorPackageManagerSupport", &emptypb.Empty{}, out); err != nil {
		return nil, err
	}
	support, err := unmarshalBytes[[]sdk.PackageManagerSupport](out.Value)
	if err != nil || support == nil {
		return nil, err
	}
	return *support, nil
}

func (c *serviceClient) Detect(ctx context.Context, req *sdk.DetectRequest) (*sdk.DetectResponse, error) {
	return invokeJSON[sdk.DetectRequest, sdk.DetectResponse](ctx, c.conn, "/bomly.plugin.v1.Plugin/Detect", req)
}

func (c *serviceClient) DetectorReady(ctx context.Context, req *sdk.DetectRequest) (*sdk.ReadyResponse, error) {
	return invokeJSON[sdk.DetectRequest, sdk.ReadyResponse](ctx, c.conn, "/bomly.plugin.v1.Plugin/DetectorReady", req)
}

func (c *serviceClient) DetectorApplicable(ctx context.Context, req *sdk.DetectRequest) (*sdk.ApplicableResponse, error) {
	return invokeJSON[sdk.DetectRequest, sdk.ApplicableResponse](ctx, c.conn, "/bomly.plugin.v1.Plugin/DetectorApplicable", req)
}

func (c *serviceClient) DetectorInstall(ctx context.Context, req *sdk.DetectRequest) (*sdk.InstallResponse, error) {
	return invokeJSON[sdk.DetectRequest, sdk.InstallResponse](ctx, c.conn, "/bomly.plugin.v1.Plugin/DetectorInstall", req)
}

func (c *serviceClient) DetectorRemediationHints(ctx context.Context, req *sdk.RemediationHintRequest) (*sdk.RemediationHintResponse, error) {
	return invokeJSON[sdk.RemediationHintRequest, sdk.RemediationHintResponse](ctx, c.conn, "/bomly.plugin.v1.Plugin/DetectorRemediationHints", req)
}

func (c *serviceClient) Match(ctx context.Context, req *sdk.MatchRequest) (*sdk.MatchResponse, error) {
	return invokeJSON[sdk.MatchRequest, sdk.MatchResponse](ctx, c.conn, "/bomly.plugin.v1.Plugin/Match", req)
}

func (c *serviceClient) MatcherDescriptor(ctx context.Context) (*sdk.MatcherDescriptor, error) {
	out := new(wrapperspb.BytesValue)
	if err := c.conn.Invoke(ctx, "/bomly.plugin.v1.Plugin/MatcherDescriptor", &emptypb.Empty{}, out); err != nil {
		return nil, err
	}
	return unmarshalBytes[sdk.MatcherDescriptor](out.Value)
}

func (c *serviceClient) MatcherReady(ctx context.Context, req *sdk.MatchRequest) (*sdk.ReadyResponse, error) {
	return invokeJSON[sdk.MatchRequest, sdk.ReadyResponse](ctx, c.conn, "/bomly.plugin.v1.Plugin/MatcherReady", req)
}

func (c *serviceClient) MatcherApplicable(ctx context.Context, req *sdk.MatchRequest) (*sdk.ApplicableResponse, error) {
	return invokeJSON[sdk.MatchRequest, sdk.ApplicableResponse](ctx, c.conn, "/bomly.plugin.v1.Plugin/MatcherApplicable", req)
}

func (c *serviceClient) Audit(ctx context.Context, req *sdk.AuditRequest) (*sdk.AuditResponse, error) {
	return invokeJSON[sdk.AuditRequest, sdk.AuditResponse](ctx, c.conn, "/bomly.plugin.v1.Plugin/Audit", req)
}

func (c *serviceClient) AuditorDescriptor(ctx context.Context) (*sdk.AuditorDescriptor, error) {
	out := new(wrapperspb.BytesValue)
	if err := c.conn.Invoke(ctx, "/bomly.plugin.v1.Plugin/AuditorDescriptor", &emptypb.Empty{}, out); err != nil {
		return nil, err
	}
	return unmarshalBytes[sdk.AuditorDescriptor](out.Value)
}

func (c *serviceClient) AuditorReady(ctx context.Context, req *sdk.AuditRequest) (*sdk.ReadyResponse, error) {
	return invokeJSON[sdk.AuditRequest, sdk.ReadyResponse](ctx, c.conn, "/bomly.plugin.v1.Plugin/AuditorReady", req)
}

func (c *serviceClient) AuditorApplicable(ctx context.Context, req *sdk.AuditRequest) (*sdk.ApplicableResponse, error) {
	return invokeJSON[sdk.AuditRequest, sdk.ApplicableResponse](ctx, c.conn, "/bomly.plugin.v1.Plugin/AuditorApplicable", req)
}

func registerPluginService(server *grpc.Server, impl *serviceServer) {
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "bomly.plugin.v1.Plugin",
		HandlerType: (*pluginServiceServer)(nil),
		Methods: []grpc.MethodDesc{
			{MethodName: "DetectorDescriptor", Handler: detectorDescriptorHandler},
			{MethodName: "DetectorPackageManagerSupport", Handler: detectorPackageManagerSupportHandler},
			{MethodName: "DetectorReady", Handler: detectorReadyHandler},
			{MethodName: "DetectorApplicable", Handler: detectorApplicableHandler},
			{MethodName: "DetectorInstall", Handler: detectorInstallHandler},
			{MethodName: "Detect", Handler: detectHandler},
			{MethodName: "DetectorRemediationHints", Handler: detectorRemediationHintsHandler},
			{MethodName: "MatcherDescriptor", Handler: matcherDescriptorHandler},
			{MethodName: "MatcherReady", Handler: matcherReadyHandler},
			{MethodName: "MatcherApplicable", Handler: matcherApplicableHandler},
			{MethodName: "Match", Handler: matchHandler},
			{MethodName: "AuditorDescriptor", Handler: auditorDescriptorHandler},
			{MethodName: "AuditorReady", Handler: auditorReadyHandler},
			{MethodName: "AuditorApplicable", Handler: auditorApplicableHandler},
			{MethodName: "Audit", Handler: auditHandler},
			{MethodName: "AnalyzerDescriptor", Handler: analyzerDescriptorHandler},
			{MethodName: "AnalyzerReady", Handler: analyzerReadyHandler},
			{MethodName: "AnalyzerApplicable", Handler: analyzerApplicableHandler},
			{MethodName: "Analyze", Handler: analyzeHandler},
		},
	}, impl)
}

func detectHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return bytesHandler(srv, ctx, dec, interceptor, "/bomly.plugin.v1.Plugin/Detect", func(ctx context.Context, req *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
		return srv.(*serviceServer).Detect(ctx, req)
	})
}

func detectorDescriptorHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	method := func(ctx context.Context, req any) (any, error) {
		return srv.(*serviceServer).DetectorDescriptor(ctx, req.(*emptypb.Empty))
	}
	if interceptor == nil {
		return method(ctx, in)
	}
	return interceptor(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: "/bomly.plugin.v1.Plugin/DetectorDescriptor"}, method)
}

func detectorPackageManagerSupportHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	method := func(ctx context.Context, req any) (any, error) {
		return srv.(*serviceServer).DetectorPackageManagerSupport(ctx, req.(*emptypb.Empty))
	}
	if interceptor == nil {
		return method(ctx, in)
	}
	return interceptor(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: "/bomly.plugin.v1.Plugin/DetectorPackageManagerSupport"}, method)
}

func detectorReadyHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return bytesHandler(srv, ctx, dec, interceptor, "/bomly.plugin.v1.Plugin/DetectorReady", func(ctx context.Context, req *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
		return srv.(*serviceServer).DetectorReady(ctx, req)
	})
}

func detectorApplicableHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return bytesHandler(srv, ctx, dec, interceptor, "/bomly.plugin.v1.Plugin/DetectorApplicable", func(ctx context.Context, req *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
		return srv.(*serviceServer).DetectorApplicable(ctx, req)
	})
}

func detectorInstallHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return bytesHandler(srv, ctx, dec, interceptor, "/bomly.plugin.v1.Plugin/DetectorInstall", func(ctx context.Context, req *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
		return srv.(*serviceServer).DetectorInstall(ctx, req)
	})
}

func detectorRemediationHintsHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return bytesHandler(srv, ctx, dec, interceptor, "/bomly.plugin.v1.Plugin/DetectorRemediationHints", func(ctx context.Context, req *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
		return srv.(*serviceServer).DetectorRemediationHints(ctx, req)
	})
}

func matchHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return bytesHandler(srv, ctx, dec, interceptor, "/bomly.plugin.v1.Plugin/Match", func(ctx context.Context, req *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
		return srv.(*serviceServer).Match(ctx, req)
	})
}

func matcherDescriptorHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	method := func(ctx context.Context, req any) (any, error) {
		return srv.(*serviceServer).MatcherDescriptor(ctx, req.(*emptypb.Empty))
	}
	if interceptor == nil {
		return method(ctx, in)
	}
	return interceptor(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: "/bomly.plugin.v1.Plugin/MatcherDescriptor"}, method)
}

func matcherReadyHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return bytesHandler(srv, ctx, dec, interceptor, "/bomly.plugin.v1.Plugin/MatcherReady", func(ctx context.Context, req *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
		return srv.(*serviceServer).MatcherReady(ctx, req)
	})
}

func matcherApplicableHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return bytesHandler(srv, ctx, dec, interceptor, "/bomly.plugin.v1.Plugin/MatcherApplicable", func(ctx context.Context, req *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
		return srv.(*serviceServer).MatcherApplicable(ctx, req)
	})
}

func auditHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return bytesHandler(srv, ctx, dec, interceptor, "/bomly.plugin.v1.Plugin/Audit", func(ctx context.Context, req *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
		return srv.(*serviceServer).Audit(ctx, req)
	})
}

func auditorDescriptorHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	method := func(ctx context.Context, req any) (any, error) {
		return srv.(*serviceServer).AuditorDescriptor(ctx, req.(*emptypb.Empty))
	}
	if interceptor == nil {
		return method(ctx, in)
	}
	return interceptor(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: "/bomly.plugin.v1.Plugin/AuditorDescriptor"}, method)
}

func auditorReadyHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return bytesHandler(srv, ctx, dec, interceptor, "/bomly.plugin.v1.Plugin/AuditorReady", func(ctx context.Context, req *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
		return srv.(*serviceServer).AuditorReady(ctx, req)
	})
}

func auditorApplicableHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return bytesHandler(srv, ctx, dec, interceptor, "/bomly.plugin.v1.Plugin/AuditorApplicable", func(ctx context.Context, req *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
		return srv.(*serviceServer).AuditorApplicable(ctx, req)
	})
}

func bytesHandler(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
	methodName string,
	handler func(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error),
) (any, error) {
	in := new(wrapperspb.BytesValue)
	if err := dec(in); err != nil {
		return nil, err
	}
	method := func(ctx context.Context, req any) (any, error) {
		return handler(ctx, req.(*wrapperspb.BytesValue))
	}
	if interceptor == nil {
		return method(ctx, in)
	}
	return interceptor(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: methodName}, method)
}

func marshalResponse[T any](ctx context.Context, fn func(context.Context) (*T, error)) (*wrapperspb.BytesValue, error) {
	value, err := fn(ctx)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}
	return wrapperspb.Bytes(data), nil
}

func invokeJSON[TReq any, TResp any](ctx context.Context, conn grpc.ClientConnInterface, method string, req *TReq) (*TResp, error) {
	if req == nil {
		return nil, errors.New("request is nil")
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	out := new(wrapperspb.BytesValue)
	if err := conn.Invoke(ctx, method, wrapperspb.Bytes(payload), out); err != nil {
		return nil, err
	}
	return unmarshalBytes[TResp](out.Value)
}

func unmarshalPayload[T any](in *wrapperspb.BytesValue) (*T, error) {
	if in == nil {
		return nil, errors.New("payload is nil")
	}
	return unmarshalBytes[T](in.Value)
}

func unmarshalBytes[T any](data []byte) (*T, error) {
	var value T
	if len(data) == 0 {
		return &value, nil
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, err
	}
	return &value, nil
}

// ServedAnalyzer is the analyzer interface implemented by external analyzer
// plugins. Analyzers read the dependency graph and PURL-keyed package registry
// and annotate Vulnerability.Reachability on registry packages.
type ServedAnalyzer interface {
	Descriptor(context.Context) (*sdk.AnalyzerDescriptor, error)
	Ready(context.Context, *sdk.AnalyzeRequest) (*sdk.ReadyResponse, error)
	Applicable(context.Context, *sdk.AnalyzeRequest) (*sdk.ApplicableResponse, error)
	Analyze(context.Context, *sdk.AnalyzeRequest) (*sdk.AnalyzeResponse, error)
}

// ServeAnalyzer serves one analyzer plugin over Bomly's managed HashiCorp
// go-plugin gRPC transport. Call it from the plugin binary's main function.
func ServeAnalyzer(analyzer ServedAnalyzer) {
	serve(nil, nil, nil, analyzer)
}

func (s *serviceServer) AnalyzerDescriptor(ctx context.Context, _ *emptypb.Empty) (*wrapperspb.BytesValue, error) {
	if s.analyzer == nil {
		return nil, status.Error(codes.Unimplemented, "analyzer not implemented")
	}
	descriptor, err := s.analyzer.Descriptor(ctx)
	if err != nil {
		return nil, err
	}
	if err := sdk.ValidateAnalyzerDescriptor(descriptor); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid analyzer descriptor: %v", err)
	}
	data, err := json.Marshal(descriptor)
	if err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}
	return wrapperspb.Bytes(data), nil
}

func (s *serviceServer) AnalyzerReady(ctx context.Context, in *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	if s.analyzer == nil {
		return nil, status.Error(codes.Unimplemented, "analyzer not implemented")
	}
	req, err := unmarshalPayload[sdk.AnalyzeRequest](in)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decode analyzer ready request: %v", err)
	}
	return marshalResponse(ctx, func(ctx context.Context) (*sdk.ReadyResponse, error) {
		return s.analyzer.Ready(ctx, req)
	})
}

func (s *serviceServer) AnalyzerApplicable(ctx context.Context, in *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	if s.analyzer == nil {
		return nil, status.Error(codes.Unimplemented, "analyzer not implemented")
	}
	req, err := unmarshalPayload[sdk.AnalyzeRequest](in)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decode analyzer applicable request: %v", err)
	}
	return marshalResponse(ctx, func(ctx context.Context) (*sdk.ApplicableResponse, error) {
		return s.analyzer.Applicable(ctx, req)
	})
}

func (s *serviceServer) Analyze(ctx context.Context, in *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	if s.analyzer == nil {
		return nil, status.Error(codes.Unimplemented, "analyzer not implemented")
	}
	req, err := unmarshalPayload[sdk.AnalyzeRequest](in)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decode analyze request: %v", err)
	}
	return marshalResponse(ctx, func(ctx context.Context) (*sdk.AnalyzeResponse, error) {
		return s.analyzer.Analyze(ctx, req)
	})
}

func analyzerDescriptorHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	method := func(ctx context.Context, req any) (any, error) {
		return srv.(*serviceServer).AnalyzerDescriptor(ctx, req.(*emptypb.Empty))
	}
	if interceptor == nil {
		return method(ctx, in)
	}
	return interceptor(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: "/bomly.plugin.v1.Plugin/AnalyzerDescriptor"}, method)
}

func analyzerReadyHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return bytesHandler(srv, ctx, dec, interceptor, "/bomly.plugin.v1.Plugin/AnalyzerReady", func(ctx context.Context, req *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
		return srv.(*serviceServer).AnalyzerReady(ctx, req)
	})
}

func analyzerApplicableHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return bytesHandler(srv, ctx, dec, interceptor, "/bomly.plugin.v1.Plugin/AnalyzerApplicable", func(ctx context.Context, req *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
		return srv.(*serviceServer).AnalyzerApplicable(ctx, req)
	})
}

func analyzeHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return bytesHandler(srv, ctx, dec, interceptor, "/bomly.plugin.v1.Plugin/Analyze", func(ctx context.Context, req *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
		return srv.(*serviceServer).Analyze(ctx, req)
	})
}

func (c *serviceClient) AnalyzerDescriptor(ctx context.Context) (*sdk.AnalyzerDescriptor, error) {
	out := new(wrapperspb.BytesValue)
	if err := c.conn.Invoke(ctx, "/bomly.plugin.v1.Plugin/AnalyzerDescriptor", &emptypb.Empty{}, out); err != nil {
		return nil, err
	}
	return unmarshalBytes[sdk.AnalyzerDescriptor](out.Value)
}

func (c *serviceClient) AnalyzerReady(ctx context.Context, req *sdk.AnalyzeRequest) (*sdk.ReadyResponse, error) {
	return invokeJSON[sdk.AnalyzeRequest, sdk.ReadyResponse](ctx, c.conn, "/bomly.plugin.v1.Plugin/AnalyzerReady", req)
}

func (c *serviceClient) AnalyzerApplicable(ctx context.Context, req *sdk.AnalyzeRequest) (*sdk.ApplicableResponse, error) {
	return invokeJSON[sdk.AnalyzeRequest, sdk.ApplicableResponse](ctx, c.conn, "/bomly.plugin.v1.Plugin/AnalyzerApplicable", req)
}

func (c *serviceClient) Analyze(ctx context.Context, req *sdk.AnalyzeRequest) (*sdk.AnalyzeResponse, error) {
	return invokeJSON[sdk.AnalyzeRequest, sdk.AnalyzeResponse](ctx, c.conn, "/bomly.plugin.v1.Plugin/Analyze", req)
}
