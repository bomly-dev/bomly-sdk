package sbom

import (
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/bomly-dev/bomly-sdk/model"
)

// A CycloneDX reference to a source document can list several hashes. The
// record keeps one, and it keeps the SHA-1 wherever it sits in the list: that
// is the only algorithm an SPDX reference can carry, so keeping a SHA-256
// listed ahead of it would drop the source from an SPDX export the document
// had supplied everything to name.
func TestCycloneDXIngestPrefersTheSHA1OfASourceReference(t *testing.T) {
	sha1Value := strings.Repeat("a", 40)
	sha256Value := strings.Repeat("b", 64)
	sha512Value := strings.Repeat("c", 128)

	for name, testCase := range map[string]struct {
		hashes []cdx.Hash
		want   model.DigestAlgorithm
	}{
		"sha256 listed before sha1": {
			hashes: []cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: sha256Value}, {Algorithm: cdx.HashAlgoSHA1, Value: sha1Value}},
			want:   model.DigestAlgorithmSHA1,
		},
		"sha1 listed first": {
			hashes: []cdx.Hash{{Algorithm: cdx.HashAlgoSHA1, Value: sha1Value}, {Algorithm: cdx.HashAlgoSHA256, Value: sha256Value}},
			want:   model.DigestAlgorithmSHA1,
		},
		"no sha1 offered keeps the first": {
			hashes: []cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: sha256Value}, {Algorithm: cdx.HashAlgoSHA512, Value: sha512Value}},
			want:   model.DigestAlgorithmSHA256,
		},
	} {
		t.Run(name, func(t *testing.T) {
			refs := []cdx.ExternalReference{{
				Type: cdx.ERTypeBOM, URL: "https://acme.example/sbom/source", Hashes: &testCase.hashes,
			}}
			sources := cycloneDXIngestedSources(&refs)
			if len(sources) != 1 || sources[0].Checksum == nil {
				t.Fatalf("sources = %+v, want one source with a checksum", sources)
			}
			if got := sources[0].Checksum.Algorithm; got != testCase.want {
				t.Fatalf("kept %q, want %q", got, testCase.want)
			}
		})
	}
}
