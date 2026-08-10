package sdk

import (
	"context"
	"encoding/json"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type stubAnalyzer struct {
	descriptor AnalyzerDescriptor
	analyze    func(context.Context, *AnalyzeRequest) (*AnalyzeResponse, error)
}

func (a stubAnalyzer) Descriptor(context.Context) (*AnalyzerDescriptor, error) {
	descriptor := a.descriptor
	return &descriptor, nil
}

func (a stubAnalyzer) Ready(context.Context, *AnalyzeRequest) (*ReadyResponse, error) {
	return &ReadyResponse{Ready: true}, nil
}

func (a stubAnalyzer) Applicable(context.Context, *AnalyzeRequest) (*ApplicableResponse, error) {
	return &ApplicableResponse{Applicable: true}, nil
}

func (a stubAnalyzer) Analyze(ctx context.Context, req *AnalyzeRequest) (*AnalyzeResponse, error) {
	if a.analyze != nil {
		return a.analyze(ctx, req)
	}
	return &AnalyzeResponse{}, nil
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
		descriptor: AnalyzerDescriptor{
			Name:               "stub-analyzer",
			SupportedLanguages: []Language{LanguageGo},
			Capabilities:       []string{CapabilityPackageUpdates},
		},
		analyze: func(_ context.Context, req *AnalyzeRequest) (*AnalyzeResponse, error) {
			if !req.AcceptPackageUpdates {
				t.Fatal("expected AcceptPackageUpdates to survive the wire")
			}
			return &AnalyzeResponse{
				PackageUpdates: []*Package{{Coordinates: Coordinates{PURL: "pkg:golang/example.com/mod@v1.0.0"}}},
				AnalyzerRuns:   []string{"stub-analyzer"},
			}, nil
		},
	}}

	out, err := server.AnalyzerDescriptor(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("AnalyzerDescriptor: %v", err)
	}
	descriptor, err := unmarshalBytes[AnalyzerDescriptor](out.Value)
	if err != nil {
		t.Fatalf("decode descriptor: %v", err)
	}
	if descriptor.Name != "stub-analyzer" || len(descriptor.Capabilities) != 1 {
		t.Fatalf("descriptor round-trip mismatch: %+v", descriptor)
	}

	readyOut, err := server.AnalyzerReady(context.Background(), encodeRequest(t, &AnalyzeRequest{}))
	if err != nil {
		t.Fatalf("AnalyzerReady: %v", err)
	}
	ready, err := unmarshalBytes[ReadyResponse](readyOut.Value)
	if err != nil || !ready.Ready {
		t.Fatalf("ready round-trip mismatch: %+v err=%v", ready, err)
	}

	applicableOut, err := server.AnalyzerApplicable(context.Background(), encodeRequest(t, &AnalyzeRequest{}))
	if err != nil {
		t.Fatalf("AnalyzerApplicable: %v", err)
	}
	applicable, err := unmarshalBytes[ApplicableResponse](applicableOut.Value)
	if err != nil || !applicable.Applicable {
		t.Fatalf("applicable round-trip mismatch: %+v err=%v", applicable, err)
	}

	analyzeOut, err := server.Analyze(context.Background(), encodeRequest(t, &AnalyzeRequest{AcceptPackageUpdates: true}))
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	result, err := unmarshalBytes[AnalyzeResponse](analyzeOut.Value)
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
			_, err := server.AnalyzerReady(context.Background(), encodeRequest(t, &AnalyzeRequest{}))
			return err
		},
		func() error {
			_, err := server.AnalyzerApplicable(context.Background(), encodeRequest(t, &AnalyzeRequest{}))
			return err
		},
		func() error {
			_, err := server.Analyze(context.Background(), encodeRequest(t, &AnalyzeRequest{}))
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
	server := &serviceServer{analyzer: stubAnalyzer{descriptor: AnalyzerDescriptor{Name: "  "}}}
	_, err := server.AnalyzerDescriptor(context.Background(), &emptypb.Empty{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for empty name, got %v", err)
	}
}

func TestValidateAnalyzerDescriptorNil(t *testing.T) {
	if err := ValidateAnalyzerDescriptor(nil); err == nil {
		t.Fatal("expected error for nil analyzer descriptor")
	}
	if err := ValidateAnalyzerDescriptor(&AnalyzerDescriptor{Name: "ok"}); err != nil {
		t.Fatalf("valid descriptor rejected: %v", err)
	}
}

func TestApplyPackageUpdates(t *testing.T) {
	registry := NewPackageRegistry()
	base := registry.Ensure("pkg:npm/left-pad@1.3.0")
	base.Name = "left-pad"

	updated := ApplyPackageUpdates(registry, []*Package{
		{Coordinates: Coordinates{PURL: "pkg:npm/left-pad@1.3.0"}, Licenses: []PackageLicense{{Value: "MIT"}}},
		{Coordinates: Coordinates{PURL: "pkg:npm/is-even@1.0.0"}},
		nil,
		{}, // no PURL: ignored
	})
	if updated != registry {
		t.Fatal("expected the same registry back")
	}
	merged, ok := registry.Get("pkg:npm/left-pad@1.3.0")
	if !ok || merged.Name != "left-pad" || len(merged.Licenses) != 1 {
		t.Fatalf("expected merged package to keep name and gain license: %+v", merged)
	}
	if _, ok := registry.Get("pkg:npm/is-even@1.0.0"); !ok {
		t.Fatal("expected new package to be added")
	}
	if got := len(registry.All()); got != 2 {
		t.Fatalf("expected 2 packages, got %d", got)
	}

	if reg := ApplyPackageUpdates(nil, nil); reg != nil {
		t.Fatal("nil registry with no updates should stay nil")
	}
	if reg := ApplyPackageUpdates(nil, []*Package{{Coordinates: Coordinates{PURL: "pkg:npm/a@1.0.0"}}}); reg == nil || len(reg.All()) != 1 {
		t.Fatal("nil registry with updates should allocate")
	}
}

func TestConfigSchemaFor(t *testing.T) {
	type nested struct {
		Region string `json:"region" doc:"Cloud region"`
	}
	type config struct {
		Endpoint string            `json:"endpoint" doc:"API endpoint override" default:"https://api.example.com"`
		Timeout  int               `json:"timeoutSeconds" doc:"Request timeout in seconds" default:"30"`
		Strict   bool              `json:"strict"`
		Skipped  string            `json:"-"`
		Labels   map[string]string `json:"labels"`
		Extra    []nested          `json:"extra"`
		hidden   string            //nolint:unused
	}

	raw, err := ConfigSchemaFor(config{})
	if err != nil {
		t.Fatalf("ConfigSchemaFor: %v", err)
	}
	var schema struct {
		Schema     string `json:"$schema"`
		Type       string `json:"type"`
		Properties map[string]struct {
			Type        string `json:"type"`
			Description string `json:"description"`
			Default     any    `json:"default"`
		} `json:"properties"`
		AdditionalProperties bool `json:"additionalProperties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	if schema.Type != "object" || schema.AdditionalProperties {
		t.Fatalf("unexpected schema envelope: %+v", schema)
	}
	if _, ok := schema.Properties["Skipped"]; ok {
		t.Fatal("json:\"-\" field must be skipped")
	}
	if _, ok := schema.Properties["hidden"]; ok {
		t.Fatal("unexported field must be skipped")
	}
	endpoint := schema.Properties["endpoint"]
	if endpoint.Type != "string" || endpoint.Description != "API endpoint override" || endpoint.Default != "https://api.example.com" {
		t.Fatalf("endpoint property mismatch: %+v", endpoint)
	}
	timeout := schema.Properties["timeoutSeconds"]
	if timeout.Type != "integer" || timeout.Default != float64(30) {
		t.Fatalf("timeout property mismatch: %+v", timeout)
	}
	if schema.Properties["labels"].Type != "object" || schema.Properties["extra"].Type != "array" {
		t.Fatalf("composite property mismatch: %+v", schema.Properties)
	}

	if _, err := ConfigSchemaFor(nil); err == nil {
		t.Fatal("nil prototype must error")
	}
	if _, err := ConfigSchemaFor("not a struct"); err == nil {
		t.Fatal("non-struct prototype must error")
	}
	var badDefault struct {
		N int `json:"n" default:"not-a-number"`
	}
	if _, err := ConfigSchemaFor(badDefault); err == nil {
		t.Fatal("invalid default must error")
	}
}
