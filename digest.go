package sdk

// Digest captures integrity information for a package artifact.
type Digest struct {
	Algorithm DigestAlgorithm `json:"algorithm,omitempty"`
	Value     string          `json:"value,omitempty"`
	// Subject says what the digest covers. Empty means the published artifact,
	// which is what most ecosystems record and what a consumer should assume.
	// It exists because some ecosystems record a hash that is not a hash of a
	// file: a Go module's "h1:" value is SHA-256 over a manifest of the source
	// tree's file hashes, not over the module zip, so a consumer that treats it
	// as an artifact digest and compares it against a downloaded file will
	// always find a mismatch.
	Subject DigestSubject `json:"subject,omitempty"`
}

// DigestSubject identifies what a digest was computed over.
type DigestSubject string

const (
	// DigestSubjectArtifact is a digest of the published file itself. It is
	// the zero value: a producer that does not say means the artifact.
	DigestSubjectArtifact DigestSubject = ""
	// DigestSubjectSourceTree is a digest over a source tree or over a
	// manifest of its file hashes, such as a Go module "h1:" dirhash.
	DigestSubjectSourceTree DigestSubject = "source-tree"
	// DigestSubjectMetadata is a digest of a package's metadata document
	// rather than of the package itself, such as a manifest or lockfile entry.
	DigestSubjectMetadata DigestSubject = "metadata"
)

// mergeDigests unions digests rather than keeping whichever record arrived
// first. Two records can carry genuinely different claims about one package --
// a hash of the published artifact from one source and a hash over the source
// tree from another -- and Subject is what tells them apart, so dropping a
// later slice would lose provenance on merge order alone.
func (p *Package) mergeDigests(incoming []Digest) {
	if len(incoming) == 0 {
		return
	}
	seen := make(map[Digest]struct{}, len(p.Digests)+len(incoming))
	for _, digest := range p.Digests {
		seen[digest] = struct{}{}
	}
	for _, digest := range incoming {
		if _, found := seen[digest]; found {
			continue
		}
		seen[digest] = struct{}{}
		p.Digests = append(p.Digests, digest)
	}
}
