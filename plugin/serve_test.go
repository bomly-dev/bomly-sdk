package plugin

import (
	"context"
	"encoding/json"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	sdk "github.com/bomly-dev/bomly-sdk"
)

type stubAnalyzer struct {
	descriptor sdk.AnalyzerDescriptor
	analyze    func(context.Context, *sdk.AnalyzeRequest) (*sdk.AnalyzeResponse, error)
}

func (a stubAnalyzer) Descriptor(context.Context) (*sdk.AnalyzerDescriptor, error) {
	descriptor := a.descriptor
	return &descriptor, nil
}

func (a stubAnalyzer) Ready(context.Context, *sdk.AnalyzeRequest) (*sdk.ReadyResponse, error) {
	return &sdk.ReadyResponse{Ready: true}, nil
}

func (a stubAnalyzer) Applicable(context.Context, *sdk.AnalyzeRequest) (*sdk.ApplicableResponse, error) {
	return &sdk.ApplicableResponse{Applicable: true}, nil
}

func (a stubAnalyzer) Analyze(ctx context.Context, req *sdk.AnalyzeRequest) (*sdk.AnalyzeResponse, error) {
	if a.analyze != nil {
		return a.analyze(ctx, req)
	}
	return &sdk.AnalyzeResponse{}, nil
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
		descriptor: sdk.AnalyzerDescriptor{
			Name:               "stub-analyzer",
			SupportedLanguages: []sdk.Language{sdk.LanguageGo},
			Capabilities:       []string{sdk.CapabilityPackageUpdates},
		},
		analyze: func(_ context.Context, req *sdk.AnalyzeRequest) (*sdk.AnalyzeResponse, error) {
			if !req.AcceptPackageUpdates {
				t.Fatal("expected AcceptPackageUpdates to survive the wire")
			}
			return &sdk.AnalyzeResponse{
				PackageUpdates: []*sdk.Package{{Coordinates: sdk.Coordinates{PURL: "pkg:golang/example.com/mod@v1.0.0"}}},
				AnalyzerRuns:   []string{"stub-analyzer"},
			}, nil
		},
	}}

	out, err := server.AnalyzerDescriptor(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("AnalyzerDescriptor: %v", err)
	}
	descriptor, err := unmarshalBytes[sdk.AnalyzerDescriptor](out.Value)
	if err != nil {
		t.Fatalf("decode descriptor: %v", err)
	}
	if descriptor.Name != "stub-analyzer" || len(descriptor.Capabilities) != 1 {
		t.Fatalf("descriptor round-trip mismatch: %+v", descriptor)
	}

	readyOut, err := server.AnalyzerReady(context.Background(), encodeRequest(t, &sdk.AnalyzeRequest{}))
	if err != nil {
		t.Fatalf("AnalyzerReady: %v", err)
	}
	ready, err := unmarshalBytes[sdk.ReadyResponse](readyOut.Value)
	if err != nil || !ready.Ready {
		t.Fatalf("ready round-trip mismatch: %+v err=%v", ready, err)
	}

	applicableOut, err := server.AnalyzerApplicable(context.Background(), encodeRequest(t, &sdk.AnalyzeRequest{}))
	if err != nil {
		t.Fatalf("AnalyzerApplicable: %v", err)
	}
	applicable, err := unmarshalBytes[sdk.ApplicableResponse](applicableOut.Value)
	if err != nil || !applicable.Applicable {
		t.Fatalf("applicable round-trip mismatch: %+v err=%v", applicable, err)
	}

	analyzeOut, err := server.Analyze(context.Background(), encodeRequest(t, &sdk.AnalyzeRequest{AcceptPackageUpdates: true}))
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	result, err := unmarshalBytes[sdk.AnalyzeResponse](analyzeOut.Value)
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
			_, err := server.AnalyzerReady(context.Background(), encodeRequest(t, &sdk.AnalyzeRequest{}))
			return err
		},
		func() error {
			_, err := server.AnalyzerApplicable(context.Background(), encodeRequest(t, &sdk.AnalyzeRequest{}))
			return err
		},
		func() error {
			_, err := server.Analyze(context.Background(), encodeRequest(t, &sdk.AnalyzeRequest{}))
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
	server := &serviceServer{analyzer: stubAnalyzer{descriptor: sdk.AnalyzerDescriptor{Name: "  "}}}
	_, err := server.AnalyzerDescriptor(context.Background(), &emptypb.Empty{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for empty name, got %v", err)
	}
}
