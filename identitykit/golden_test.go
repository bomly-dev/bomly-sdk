package identitykit

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// The golden vectors are the machine-readable half of SPEC.md: they pin the
// exact bytes of the facet encoding, the address, and the readable-ID join
// and split, so independent implementations must agree with this package
// byte for byte. Never regenerate a vector to "fix" a failing test — a
// failure here means the change under review moves the published identity
// format.
type identityVectors struct {
	AddressVectors []struct {
		Name            string `json:"name"`
		PackageIdentity string `json:"package_identity"`
		OccurrenceFacet string `json:"occurrence_facet"`
		EncodingHex     string `json:"encoding_hex"`
		Address         string `json:"address"`
	} `json:"address_vectors"`
	FallbackVectors []struct {
		Name   string    `json:"name"`
		Fields [6]string `json:"fields"`
		ID     string    `json:"id"`
	} `json:"fallback_vectors"`
	ReadableVectors []struct {
		Name        string `json:"name"`
		Base        string `json:"base"`
		Suffix      string `json:"suffix"`
		ID          string `json:"id"`
		SplitBase   string `json:"split_base"`
		SplitSuffix string `json:"split_suffix"`
	} `json:"readable_vectors"`
}

func loadVectors(t *testing.T) identityVectors {
	t.Helper()
	data, err := os.ReadFile("testdata/identity_vectors.json")
	if err != nil {
		t.Fatalf("reading golden vectors: %v", err)
	}
	var vectors identityVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("decoding golden vectors: %v", err)
	}
	if len(vectors.AddressVectors) == 0 || len(vectors.FallbackVectors) == 0 || len(vectors.ReadableVectors) == 0 {
		t.Fatal("golden vectors file is missing a vector family")
	}
	return vectors
}

func TestGoldenAddressVectors(t *testing.T) {
	vectors := loadVectors(t)
	addresses := make(map[string]string, len(vectors.AddressVectors))
	for _, vector := range vectors.AddressVectors {
		encoded := EncodeFacetsV1(vector.PackageIdentity, vector.OccurrenceFacet)
		if got := hex.EncodeToString(encoded); got != vector.EncodingHex {
			t.Errorf("%s: encoding = %s, want %s", vector.Name, got, vector.EncodingHex)
		}
		if got := AddressV1(vector.PackageIdentity, vector.OccurrenceFacet); got != vector.Address {
			t.Errorf("%s: address = %s, want %s", vector.Name, got, vector.Address)
		}
		addresses[vector.Name] = vector.Address
	}
	// The coincidence pair pins the stated limitation: identical stable
	// facets share an address by design.
	if addresses["facet-coincidence-a"] == "" || addresses["facet-coincidence-a"] != addresses["facet-coincidence-b"] {
		t.Error("facet-coincidence vectors must share one address")
	}
	// And distinct facet sets must not collide anywhere else.
	seen := make(map[string]string, len(addresses))
	for name, address := range addresses {
		if name == "facet-coincidence-b" {
			continue
		}
		if other, ok := seen[address]; ok {
			t.Errorf("vectors %s and %s share address %s", name, other, address)
		}
		seen[address] = name
	}
}

func TestGoldenFallbackVectors(t *testing.T) {
	for _, vector := range loadVectors(t).FallbackVectors {
		id := FallbackIdentity(vector.Fields[0], vector.Fields[1], vector.Fields[2], vector.Fields[3], vector.Fields[4], vector.Fields[5])
		if id != vector.ID {
			t.Errorf("%s: FallbackIdentity = %q, want %q", vector.Name, id, vector.ID)
		}
		fields, ok := ParseFallbackIdentity(vector.ID)
		if !ok || fields != vector.Fields {
			t.Errorf("%s: ParseFallbackIdentity(%q) = (%q, %v)", vector.Name, vector.ID, fields, ok)
		}
	}
}

func TestGoldenReadableVectors(t *testing.T) {
	for _, vector := range loadVectors(t).ReadableVectors {
		if got := JoinID(vector.Base, vector.Suffix); got != vector.ID {
			t.Errorf("%s: JoinID = %q, want %q", vector.Name, got, vector.ID)
		}
		base, suffix := SplitID(vector.ID)
		if base != vector.SplitBase || suffix != vector.SplitSuffix {
			t.Errorf("%s: SplitID(%q) = (%q, %q), want (%q, %q)", vector.Name, vector.ID, base, suffix, vector.SplitBase, vector.SplitSuffix)
		}
	}
}
