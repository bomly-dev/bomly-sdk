package runtime

import (
	"context"
	"encoding/json"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

type stubAnalyzer struct {
	descriptor plugin.AnalyzerDescriptor
	analyze    func(context.Context, *plugin.AnalyzeRequest) (*plugin.AnalyzeResponse, error)
}

func (a stubAnalyzer) Descriptor(context.Context) (*plugin.AnalyzerDescriptor, error) {
	descriptor := a.descriptor
	return &descriptor, nil
}

func (a stubAnalyzer) Ready(context.Context, *plugin.AnalyzeRequest) (*plugin.ReadyResponse, error) {
	return &plugin.ReadyResponse{Ready: true}, nil
}

func (a stubAnalyzer) Applicable(context.Context, *plugin.AnalyzeRequest) (*plugin.ApplicableResponse, error) {
	return &plugin.ApplicableResponse{Applicable: true}, nil
}

func (a stubAnalyzer) Analyze(ctx context.Context, req *plugin.AnalyzeRequest) (*plugin.AnalyzeResponse, error) {
	if a.analyze != nil {
		return a.analyze(ctx, req)
	}
	return &plugin.AnalyzeResponse{}, nil
}

func encodeRequest(t *testing.T, value any) *wrapperspb.BytesValue {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return wrapperspb.Bytes(data)
}

func TestServiceServerAnalyzerRoundTrip(t *testing.T) {
	server := &serviceServer{analyzer: stubAnalyzer{
		descriptor: plugin.AnalyzerDescriptor{
			Name:               "stub-analyzer",
			SupportedLanguages: []model.Language{model.LanguageGo},
			Capabilities:       []string{plugin.CapabilityPackageUpdates},
		},
		analyze: func(_ context.Context, req *plugin.AnalyzeRequest) (*plugin.AnalyzeResponse, error) {
			if !req.AcceptPackageUpdates {
				t.Fatal("expected AcceptPackageUpdates to survive the wire")
			}
			return &plugin.AnalyzeResponse{
				PackageUpdates: []*model.Package{{Coordinates: model.Coordinates{PURL: "pkg:golang/example.com/mod@v1.0.0"}}},
				AnalyzerRuns:   []string{"stub-analyzer"},
			}, nil
		},
	}}

	out, err := server.AnalyzerDescriptor(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("AnalyzerDescriptor: %v", err)
	}
	descriptor, err := unmarshalBytes[plugin.AnalyzerDescriptor](out.Value)
	if err != nil {
		t.Fatalf("decode descriptor: %v", err)
	}
	if descriptor.Name != "stub-analyzer" || len(descriptor.Capabilities) != 1 {
		t.Fatalf("descriptor round-trip mismatch: %+v", descriptor)
	}

	readyOut, err := server.AnalyzerReady(context.Background(), encodeRequest(t, &plugin.AnalyzeRequest{}))
	if err != nil {
		t.Fatalf("AnalyzerReady: %v", err)
	}
	ready, err := unmarshalBytes[plugin.ReadyResponse](readyOut.Value)
	if err != nil || !ready.Ready {
		t.Fatalf("ready round-trip mismatch: %+v err=%v", ready, err)
	}

	applicableOut, err := server.AnalyzerApplicable(context.Background(), encodeRequest(t, &plugin.AnalyzeRequest{}))
	if err != nil {
		t.Fatalf("AnalyzerApplicable: %v", err)
	}
	applicable, err := unmarshalBytes[plugin.ApplicableResponse](applicableOut.Value)
	if err != nil || !applicable.Applicable {
		t.Fatalf("applicable round-trip mismatch: %+v err=%v", applicable, err)
	}

	analyzeOut, err := server.Analyze(context.Background(), encodeRequest(t, &plugin.AnalyzeRequest{AcceptPackageUpdates: true}))
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	result, err := unmarshalBytes[plugin.AnalyzeResponse](analyzeOut.Value)
	if err != nil {
		t.Fatalf("decode analyze response: %v", err)
	}
	if len(result.PackageUpdates) != 1 || result.PackageUpdates[0].PURL != "pkg:golang/example.com/mod@v1.0.0" {
		t.Fatalf("package updates round-trip mismatch: %+v", result)
	}
}

func TestServiceServerAnalyzerUnimplemented(t *testing.T) {
	server := &serviceServer{}
	calls := []func() error{
		func() error { _, err := server.AnalyzerDescriptor(context.Background(), &emptypb.Empty{}); return err },
		func() error {
			_, err := server.AnalyzerReady(context.Background(), encodeRequest(t, &plugin.AnalyzeRequest{}))
			return err
		},
		func() error {
			_, err := server.AnalyzerApplicable(context.Background(), encodeRequest(t, &plugin.AnalyzeRequest{}))
			return err
		},
		func() error {
			_, err := server.Analyze(context.Background(), encodeRequest(t, &plugin.AnalyzeRequest{}))
			return err
		},
	}
	for idx, call := range calls {
		err := call()
		if status.Code(err) != codes.Unimplemented {
			t.Fatalf("call %d: expected Unimplemented, got %v", idx, err)
		}
	}
}

func TestServiceServerAnalyzerDescriptorValidated(t *testing.T) {
	server := &serviceServer{analyzer: stubAnalyzer{descriptor: plugin.AnalyzerDescriptor{Name: "  "}}}
	_, err := server.AnalyzerDescriptor(context.Background(), &emptypb.Empty{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for empty name, got %v", err)
	}
}
