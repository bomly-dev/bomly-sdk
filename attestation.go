package sdk

// PackageAttestation records a signed statement about how a package was built
// or published: an in-toto statement such as SLSA provenance, or a
// publish-time signature.
//
// Bomly does not fetch or verify attestations today. The type exists so a
// matcher that does can attach what it found without a model change, and so
// consumers can tell a verified statement from one that was merely present --
// a distinction that matters more than the statement itself, and that is
// easily lost when provenance data is carried in untyped metadata.
type PackageAttestation struct {
	// PredicateType identifies what the statement asserts, using the in-toto
	// predicate vocabulary (for example "https://slsa.dev/provenance/v1").
	PredicateType string `json:"predicate_type,omitempty"`
	// Source names the component or service that attached the statement, in
	// the same style as PackageScorecard.Source.
	Source string `json:"source,omitempty"`
	// URL is where the statement can be fetched.
	URL string `json:"url,omitempty"`
	// Digest identifies the statement itself, so two fetches of one URL can be
	// told apart.
	Digest *Digest `json:"digest,omitempty"`
	// Issuer is the identity that signed the statement -- an OIDC identity, a
	// key id, or a registry account -- as reported by whatever verified it.
	Issuer string `json:"issuer,omitempty"`
	// Verified records that the component attaching this statement checked its
	// signature. False means the statement was found but not verified, which is
	// weaker evidence rather than evidence of tampering; consumers must not
	// present an unverified statement as proof of provenance.
	Verified bool `json:"verified,omitempty"`
}

// mergeAttestations folds incoming statements into p, keeping one record per
// distinct statement. Several components can attest to one package -- a build
// provenance statement from one, a publish signature from another -- so this
// unions rather than keeping whichever arrived first, the way vulnerabilities
// already do. When two records describe the same statement and either verified
// it, the merged record is verified: verification is a fact one component
// established, not an opinion.
func (p *Package) mergeAttestations(incoming []PackageAttestation) {
	if len(incoming) == 0 {
		return
	}
	for _, candidate := range incoming {
		merged := false
		for i := range p.Attestations {
			if !p.Attestations[i].describesSame(candidate) {
				continue
			}
			p.Attestations[i].absorb(candidate)
			merged = true
			break
		}
		if !merged {
			p.Attestations = append(p.Attestations, candidate.Clone())
		}
	}
}

// describesSame reports whether two records can be folded into one. Verification
// is a fact about a statement *and a signer*, so records fold only when they
// agree on the issuer -- or when one of them claims nothing that could be
// misattributed.
//
// A record with no issuer and no verification says only that the statement
// exists, which any other record for it already says, so it folds into
// anything. A record with no issuer that *was* verified is a real claim ("this
// was verified, signer unrecorded") and stays separate from a record naming an
// issuer: merging them would report that issuer as verified on the strength of
// a verification that may have been of someone else's signature.
func (a PackageAttestation) describesSame(other PackageAttestation) bool {
	if a.key() != other.key() {
		return false
	}
	switch {
	case a.Issuer == other.Issuer:
		return true
	case a.claimsNothing(), other.claimsNothing():
		return true
	default:
		return false
	}
}

// claimsNothing reports whether a asserts anything beyond the statement's
// existence.
func (a PackageAttestation) claimsNothing() bool {
	return a.Issuer == "" && !a.Verified
}

// absorb folds a record describing the same statement into a. Verification
// never moves between issuers: it travels only when this record claims nothing,
// in which case the other record replaces it wholesale.
func (a *PackageAttestation) absorb(other PackageAttestation) {
	switch {
	case a.claimsNothing():
		*a = other.Clone()
	case other.claimsNothing():
		// Nothing to take.
	case other.Verified:
		// Same issuer, so the verification is this issuer's.
		a.Verified = true
	}
}

// attestationKey identifies one statement for deduplication. Issuer is
// deliberately absent: it is compared separately, because an unknown issuer is
// compatible with a known one while two known issuers are not.
type attestationKey struct {
	source          string
	predicateType   string
	url             string
	digestAlgorithm DigestAlgorithm
	digestValue     string
	digestSubject   DigestSubject
}

// key returns a's deduplication identity.
func (a PackageAttestation) key() attestationKey {
	key := attestationKey{source: a.Source, predicateType: a.PredicateType, url: a.URL}
	if a.Digest != nil {
		// The three parts stay separate rather than joined: plugin-supplied
		// values can contain the separator, and joining lets two different
		// digests produce one key.
		//
		// Subject is part of the identity: the same bytes hashed over a source
		// tree and over an artifact are different claims.
		key.digestAlgorithm = a.Digest.Algorithm
		key.digestValue = a.Digest.Value
		key.digestSubject = a.Digest.Subject
	}
	return key
}

// Clone returns a deep copy.
func (a PackageAttestation) Clone() PackageAttestation {
	clone := a
	if a.Digest != nil {
		digest := *a.Digest
		clone.Digest = &digest
	}
	return clone
}
