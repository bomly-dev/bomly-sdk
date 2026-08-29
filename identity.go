package sdk

import (
	"strings"

	"github.com/bomly-dev/bomly-sdk/identitykit"
	"github.com/bomly-dev/bomly-sdk/purlkit"
)

// FirstPartyOccurrenceFacet is the occurrence facet finalization assigns to
// the scanned project's own record when its package identity is contested
// (ADR-0036 in bomly-cli's dev-docs/adr). The bytes are fixed by the
// identity spec (identitykit/SPEC.md). The sentinel enters the record's
// content address, but the first-party record keeps the canonical
// unsuffixed readable ID — external contradicting records carry the
// suffixes.
const FirstPartyOccurrenceFacet = "first-party"

// PackageIdentity returns the readable rendering of the package-identity
// facet (ADR-0036): the identity form of the canonical package URL when one
// is derivable — qualifiers filtered through purlkit's identity allowlist,
// subpath preserved — and otherwise the escaped coordinate fallback over
// the tuple (ecosystem, package manager, type, org, name, version), taken
// only after identity normalization has run on a scratch copy. The receiver
// is never mutated and no normalization metadata is recorded. The result is
// "" only when every identity field is empty.
//
// Unlike the deprecated StableID, the rendering is ecosystem-qualified: npm
// and PyPI "left-pad@1.0.0" are two identities.
func (i Coordinates) PackageIdentity() string {
	scratch := Dependency{Coordinates: i}
	normalizeIdentityFields(&scratch)
	if purl := scratch.CanonicalPURL(); purl != "" {
		if identity := purlkit.IdentityForm(purl); identity != "" {
			return identity
		}
	}
	ecosystem := strings.TrimSpace(string(scratch.Ecosystem))
	manager := strings.TrimSpace(scratch.PackageManager.Name())
	pkgType := strings.TrimSpace(string(scratch.Type))
	if ecosystem == "" && manager == "" && pkgType == "" &&
		scratch.Org == "" && scratch.Name == "" && scratch.Version == "" {
		return ""
	}
	return identitykit.FallbackIdentity(ecosystem, manager, pkgType, scratch.Org, scratch.Name, scratch.Version)
}

// PackageIdentity returns the readable package-identity facet rendering for
// the dependency. See Coordinates.PackageIdentity.
func (d *Dependency) PackageIdentity() string {
	if d == nil {
		return ""
	}
	return d.Coordinates.PackageIdentity()
}

// OccurrenceFacet returns the durable occurrence qualifier assigned by
// identity finalization, or "" for the default occurrence — and always ""
// before finalization has run. The facet is in-process state: it is
// deliberately absent from the wire, so a consumer on the far side of a
// plugin boundary — or any holder of a JSON-decoded graph — recovers
// facets and content addresses by re-running FinalizeGraphIdentity, whose
// derivation is wire-stable: it admits only codec-surviving origin state,
// so it reproduces the sender's facets and addresses exactly.
func (d *Dependency) OccurrenceFacet() string {
	if d == nil {
		return ""
	}
	return d.occurrenceFacet
}

// ContentAddress returns the node's v1 content address: the 128-bit
// truncated SHA-256 over the versioned facet encoding of (package identity,
// occurrence facet), as 32 lowercase hex characters (identitykit.AddressV1;
// the byte layout is fixed by identitykit/SPEC.md). The address is defined
// only over finalized facets — computing it is a post-consolidation
// operation, and anything that caches identity earlier must rekey after
// finalization. It identifies the stable occurrence class of the node,
// never a per-node primary key: occurrences distinguishable only by raw
// evidence share an address by design. The address is derived, never
// stored — it can always be recomputed from the facets.
func (d *Dependency) ContentAddress() string {
	if d == nil {
		return ""
	}
	return identitykit.AddressV1(d.PackageIdentity(), d.occurrenceFacet)
}

// identityOriginFacet renders the occurrence facet for an origin under the
// identity admission rule (ADR-0036). Admission derives only from the
// codec-surviving normalized origin — the exact view DependencyOrigin's
// JSON hooks persist — so a facet assigned before a graph crosses the
// plugin wire re-derives identically afterwards; deriving from raw fields
// the codec drops would let one record's ID and address silently change
// across the boundary. This satisfies the ADR's stricter-than-publication
// rule by construction: a signed or tokenized artifact query (?token=...,
// ?X-Amz-Signature=...) is a rotating credential, and ADR-0033
// normalization already rejects any query-carrying artifact URL outright,
// so no admitted facet can carry one; fragments are dropped and the
// repository form strips query and fragment the same way. The facet
// renderings are fixed by the identity spec: "first-party" (the sentinel
// constant), "artifact" NUL url, and "repository" NUL url NUL revision,
// with an absent revision as an empty trailing field. NUL joining is
// injective here because normalized URLs and the revision charset are
// control-free.
func identityOriginFacet(origin *DependencyOrigin) (string, bool) {
	normalized := origin.Normalized()
	if normalized == nil {
		return "", false
	}
	if normalized.ArtifactURL != "" {
		return "artifact\x00" + normalized.ArtifactURL, true
	}
	return "repository\x00" + normalized.Repository + "\x00" + normalized.Revision, true
}
