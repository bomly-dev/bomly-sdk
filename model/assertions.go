package model

// Assertions are the component-level claims a source makes about one
// package: what a document, a lockfile or a registry said about it, as
// opposed to what it is (Coordinates) or where it was found (locations).
// They are one type because they are one set of claims with one set of
// gates and merge rules, carried by both DependencyNode -- where a
// detecting or ingesting source asserts them, before matching has produced
// a package -- and Package, where matching enriches them. Before this type
// existed the two carried the same eleven fields separately and each
// re-stated the gates (ADR-0037).
//
// Embedding keeps both wire shapes flat: the JSON keys are the same ones
// each struct wrote before, promoted through the embedded field.
//
// Gates, applied on both wire directions and again when a node seeds a
// registry package: NormalizeDescription (trimmed, bounded, control
// characters dropped); NormalizeHomepage (URLFormReference, so a bare host
// and a query are fine while credentials and local paths are cleared);
// Contact.Normalized for both contacts, which yields nil for an
// unpublishable party and never retains an email address;
// ExternalReference.Normalized; Digest.Normalized; PackageLicense.Normalized.
//
// Merge classes: Description, Homepage, Supplier, Originator and Copyright
// are scalars, fill-gaps -- both witnesses are gated before the gap is
// measured, so a value that could not be published never blocks one that
// can. ExternalReferences, CPEs, Digests and Licenses are sets, unioned:
// every witness's claims survive, because two sources can each know
// something the other does not, and a declaration and a conclusion are two
// claims about one package rather than one overriding the other.
type Assertions struct {
	// Description is the package's own summary of itself. SPDX
	// PackageDescription / CycloneDX component description.
	Description string `json:"description,omitempty"`
	// Homepage is the package's project page. SPDX PackageHomePage /
	// CycloneDX external reference of type website.
	Homepage string `json:"homepage,omitempty"`
	// Supplier is who distributed the package. SPDX PackageSupplier /
	// CycloneDX supplier.
	Supplier *Contact `json:"supplier,omitempty"`
	// Originator is who originally authored the package, which is often not
	// the supplier. SPDX PackageOriginator / CycloneDX author or publisher.
	Originator *Contact `json:"originator,omitempty"`
	// ExternalReferences are the references a source attached to the
	// package: advisories, repositories, package-manager coordinates. SPDX
	// externalRefs / CycloneDX externalReferences.
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
	// CPEs are the CPE identifiers a source asserted for the package.
	CPEs []string `json:"cpes,omitempty"`
	// Digests are the integrity claims a source made over the package's
	// artifact, source or metadata.
	Digests []Digest `json:"digests,omitempty"`
	// Licenses are the license claims a source made, each typed declared or
	// concluded.
	Licenses []PackageLicense `json:"licenses,omitempty"`
	// Copyright is the copyright text a source stated. Gate:
	// NormalizeCopyright -- trimmed and bounded, control characters other
	// than line breaks and tabs dropped, an over-long notice cleared rather
	// than truncated.
	Copyright string `json:"copyright,omitempty"`
}

// Normalized returns the assertions with every field held to its gate.
// Values that cannot be published are cleared rather than corrected,
// following the codecs on DependencyOrigin and Contact; the sets are
// deduplicated and sorted so the result is byte-stable.
func (a Assertions) Normalized() Assertions {
	return Assertions{
		Description:        NormalizeDescription(a.Description),
		Homepage:           NormalizeHomepage(a.Homepage),
		Supplier:           normalizedContact(a.Supplier),
		Originator:         normalizedContact(a.Originator),
		ExternalReferences: MergeExternalReferences(nil, a.ExternalReferences),
		CPEs:               mergeStringSet(nil, a.CPEs),
		Digests:            mergeDigestSet(nil, a.Digests),
		Licenses:           MergeLicenses(nil, a.Licenses),
		Copyright:          NormalizeCopyright(a.Copyright),
	}
}

// MergeFrom folds src into a under the declared merge classes: scalars keep
// a's value and take src's only to fill a gap, sets union. Both sides are
// gated first -- a holder built in process never passed a codec, so a may
// hold an unpublishable value that is non-empty, would block a valid
// incoming one, and would then be dropped at encode.
func (a *Assertions) MergeFrom(src Assertions) {
	if a == nil {
		return
	}
	left, right := a.Normalized(), src.Normalized()
	if left.Description == "" {
		left.Description = right.Description
	}
	if left.Homepage == "" {
		left.Homepage = right.Homepage
	}
	if left.Supplier == nil {
		left.Supplier = right.Supplier
	}
	if left.Originator == nil {
		left.Originator = right.Originator
	}
	if left.Copyright == "" {
		left.Copyright = right.Copyright
	}
	left.ExternalReferences = MergeExternalReferences(left.ExternalReferences, right.ExternalReferences)
	left.CPEs = mergeStringSet(left.CPEs, right.CPEs)
	left.Digests = mergeDigestSet(left.Digests, right.Digests)
	left.Licenses = MergeLicenses(left.Licenses, right.Licenses)
	*a = left
}

// Clone returns a deep copy.
func (a Assertions) Clone() Assertions {
	clone := a
	clone.CPEs = cloneStrings(a.CPEs)
	if len(a.Digests) > 0 {
		clone.Digests = append([]Digest(nil), a.Digests...)
	}
	clone.ExternalReferences = cloneExternalReferences(a.ExternalReferences)
	if len(a.Licenses) > 0 {
		clone.Licenses = append([]PackageLicense(nil), a.Licenses...)
	}
	clone.Supplier = a.Supplier.Clone()
	clone.Originator = a.Originator.Clone()
	return clone
}
