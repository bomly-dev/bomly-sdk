package sdk

import (
	"context"
	"encoding/json"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// ServedAnalyzer is the analyzer interface implemented by external analyzer
// plugins. Analyzers read the dependency graph and PURL-keyed package registry
// and annotate Vulnerability.Reachability on registry packages.
type ServedAnalyzer interface {
	Descriptor(context.Context) (*AnalyzerDescriptor, error)
	Ready(context.Context, *AnalyzeRequest) (*ReadyResponse, error)
	Applicable(context.Context, *AnalyzeRequest) (*ApplicableResponse, error)
	Analyze(context.Context, *AnalyzeRequest) (*AnalyzeResponse, error)
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
	if err := ValidateAnalyzerDescriptor(descriptor); err != nil {
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
	req, err := unmarshalPayload[AnalyzeRequest](in)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decode analyzer ready request: %v", err)
	}
	return marshalResponse(ctx, func(ctx context.Context) (*ReadyResponse, error) {
		return s.analyzer.Ready(ctx, req)
	})
}

func (s *serviceServer) AnalyzerApplicable(ctx context.Context, in *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	if s.analyzer == nil {
		return nil, status.Error(codes.Unimplemented, "analyzer not implemented")
	}
	req, err := unmarshalPayload[AnalyzeRequest](in)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decode analyzer applicable request: %v", err)
	}
	return marshalResponse(ctx, func(ctx context.Context) (*ApplicableResponse, error) {
		return s.analyzer.Applicable(ctx, req)
	})
}

func (s *serviceServer) Analyze(ctx context.Context, in *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	if s.analyzer == nil {
		return nil, status.Error(codes.Unimplemented, "analyzer not implemented")
	}
	req, err := unmarshalPayload[AnalyzeRequest](in)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decode analyze request: %v", err)
	}
	return marshalResponse(ctx, func(ctx context.Context) (*AnalyzeResponse, error) {
		return s.analyzer.Analyze(ctx, req)
	})
}

func analyzerDescriptorHandler(srv interface{}, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
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

func analyzerReadyHandler(srv interface{}, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return bytesHandler(srv, ctx, dec, interceptor, "/bomly.plugin.v1.Plugin/AnalyzerReady", func(ctx context.Context, req *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
		return srv.(*serviceServer).AnalyzerReady(ctx, req)
	})
}

func analyzerApplicableHandler(srv interface{}, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return bytesHandler(srv, ctx, dec, interceptor, "/bomly.plugin.v1.Plugin/AnalyzerApplicable", func(ctx context.Context, req *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
		return srv.(*serviceServer).AnalyzerApplicable(ctx, req)
	})
}

func analyzeHandler(srv interface{}, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return bytesHandler(srv, ctx, dec, interceptor, "/bomly.plugin.v1.Plugin/Analyze", func(ctx context.Context, req *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
		return srv.(*serviceServer).Analyze(ctx, req)
	})
}

func (c *serviceClient) AnalyzerDescriptor(ctx context.Context) (*AnalyzerDescriptor, error) {
	out := new(wrapperspb.BytesValue)
	if err := c.conn.Invoke(ctx, "/bomly.plugin.v1.Plugin/AnalyzerDescriptor", &emptypb.Empty{}, out); err != nil {
		return nil, err
	}
	return unmarshalBytes[AnalyzerDescriptor](out.Value)
}

func (c *serviceClient) AnalyzerReady(ctx context.Context, req *AnalyzeRequest) (*ReadyResponse, error) {
	return invokeJSON[AnalyzeRequest, ReadyResponse](ctx, c.conn, "/bomly.plugin.v1.Plugin/AnalyzerReady", req)
}

func (c *serviceClient) AnalyzerApplicable(ctx context.Context, req *AnalyzeRequest) (*ApplicableResponse, error) {
	return invokeJSON[AnalyzeRequest, ApplicableResponse](ctx, c.conn, "/bomly.plugin.v1.Plugin/AnalyzerApplicable", req)
}

func (c *serviceClient) Analyze(ctx context.Context, req *AnalyzeRequest) (*AnalyzeResponse, error) {
	return invokeJSON[AnalyzeRequest, AnalyzeResponse](ctx, c.conn, "/bomly.plugin.v1.Plugin/Analyze", req)
}
