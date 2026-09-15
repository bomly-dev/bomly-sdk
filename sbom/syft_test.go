package sbom

import (
	"errors"
	"testing"
)

// A syft-json document is recognized so the refusal can name the conversion
// path, and never decoded. The fixture is the shape syft writes: an artifacts
// list and a schema.url under anchore/syft. The guard that runs this sniff
// against syft's own encoder stays in the syft-detector plugin, which already
// links syft; this module does not, on purpose (see syftSchemaURLMarker).
func TestSyftJSONIsRecognizedAndRefused(t *testing.T) {
	const syftJSON = `{"artifacts":[],"artifactRelationships":[],` +
		`"source":{"id":"x","name":"demo","version":"1","type":"directory"},` +
		`"descriptor":{"name":"syft","version":"1.0.0"},` +
		`"schema":{"version":"16.0.34","url":"https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.0.34.json"}}`

	target, err := DetectJSONTarget([]byte(syftJSON))
	if err != nil || target != TargetSyftJSON {
		t.Fatalf("DetectJSONTarget(syft output) = (%q, %v), want the syft target", target, err)
	}
	doc, target, err := UnmarshalAutoJSON([]byte(syftJSON))
	if !errors.Is(err, ErrSyftJSONUnsupported) {
		t.Fatalf("UnmarshalAutoJSON(syft output) error = %v, want %v", err, ErrSyftJSONUnsupported)
	}
	if doc != nil || target != TargetSyftJSON {
		t.Fatalf("UnmarshalAutoJSON(syft output) = (%v, %q), want no document and the syft target named", doc, target)
	}
	if _, err := UnmarshalJSON([]byte(syftJSON), TargetSyftJSON); !errors.Is(err, ErrUnsupportedTarget) {
		t.Fatalf("UnmarshalJSON(TargetSyftJSON) error = %v, want %v: the target has no codec", err, ErrUnsupportedTarget)
	}

	// A schema.url that is not syft's must not be mistaken for it.
	notSyft := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[],"schema":{"url":"https://example.com/schema.json"}}`)
	if target, err := DetectJSONTarget(notSyft); err != nil || target != TargetCycloneDX16JSON {
		t.Fatalf("DetectJSONTarget(non-syft) = (%q, %v), want the cyclonedx target", target, err)
	}
}
