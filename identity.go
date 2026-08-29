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
// deliberately absent from the wire, and a record decoded from JSON
// recomputes it by re-running finalization.
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
// stored — it can always be recomputed from the facets. For a node with no
// derivable package identity, the package facet is the readable base of
// its supplied ID (discriminators and suffixes stripped), so distinct
// custom-ID nodes keep distinct addresses.
func (d *Dependency) ContentAddress() string {
	if d == nil {
		return ""
	}
	packageFacet := d.PackageIdentity()
	if packageFacet == "" {
		packageFacet = identityFallbackBase(d.ID)
	}
	return identitykit.AddressV1(packageFacet, d.occurrenceFacet)
}

// identityOriginFacet renders the occurrence facet for an origin under the
// identity admission rule (ADR-0036), which is deliberately stricter than
// the ADR-0033 publication rule: the artifact URL has its query and
// fragment stripped BEFORE origin normalization, because a signed or
// tokenized artifact query (?token=..., ?X-Amz-Signature=...) is a rotating
// credential that must not shape a persistent identity — while the
// published origin field keeps ADR-0033's own semantics untouched. The
// repository form already strips query and fragment under ADR-0033. The
// facet renderings are fixed by the identity spec: "first-party" (the
// sentinel constant), "artifact" NUL url, and "repository" NUL url NUL
// revision, with an invalid or absent revision as an empty trailing field.
// NUL joining is injective here because normalized URLs and the revision
// charset are control-free.
func identityOriginFacet(origin *DependencyOrigin) (string, bool) {
	if origin == nil {
		return "", false
	}
	if artifact := stripRawQueryFragment(origin.ArtifactURL); artifact != "" {
		if normalized, ok := NormalizeOriginURL(artifact, false); ok {
			return "artifact\x00" + normalized, true
		}
	}
	if repository, ok := NormalizeOriginURL(origin.Repository, true); ok {
		facet := "repository\x00" + repository + "\x00"
		if revision := strings.TrimSpace(origin.Revision); isValidOriginRevision(revision) {
			facet += revision
		}
		return facet, true
	}
	return "", false
}

// stripRawQueryFragment cuts a raw URL at its first '?' or '#'. It runs on
// the raw value, before parsing: identity admission must never see the
// query bytes at all, and a URL malformed enough to confuse a parser still
// has its query removed by position.
func stripRawQueryFragment(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if i := strings.IndexAny(trimmed, "?#"); i >= 0 {
		trimmed = strings.TrimSpace(trimmed[:i])
	}
	return trimmed
}
