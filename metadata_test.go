package sdk

import "testing"

// TestReservedMetadataPrefixCoversTheKeysBomlyOwns pins that the policy
// recognizes the keys this module actually defines. A reserved prefix that
// does not match its own keys protects nothing.
func TestReservedMetadataPrefixCoversTheKeysBomlyOwns(t *testing.T) {
	if !IsReservedMetadataKey(MetadataKeyDetectionLicenses) {
		t.Errorf("%q is a Bomly key but is not reserved", MetadataKeyDetectionLicenses)
	}
	// An ecosystem key that is not namespaced stays a plugin's to use.
	if IsReservedMetadataKey(MetadataKeyNPM) {
		t.Errorf("%q was treated as reserved", MetadataKeyNPM)
	}
}

// TestReservedMetadataKeysIsCaseInsensitiveAndSorted pins that a key
// differing only in case is still a collision, and that the report is stable.
func TestReservedMetadataKeysIsCaseInsensitiveAndSorted(t *testing.T) {
	got := ReservedMetadataKeys(map[string]any{
		"bomly.zeta":  1,
		"BOMLY.alpha": 2,
		"  bomly.mid": 3,
		"npm":         4,
		"vendor.x":    5,
	})
	if len(got) != 3 {
		t.Fatalf("got %v, want the three reserved keys", got)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Errorf("not sorted: %v", got)
			break
		}
	}
	if len(ReservedMetadataKeys(nil)) != 0 {
		t.Error("a nil map reported reserved keys")
	}
}
