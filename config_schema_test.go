package sdk

import (
	"encoding/json"
	"testing"
)

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
