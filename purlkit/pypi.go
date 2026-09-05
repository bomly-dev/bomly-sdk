package purlkit

import (
	"strings"

	pep440 "github.com/aquasecurity/go-pep440-version"
)

// pypiType is the package URL type whose versions PEP 440 governs.
const pypiType = "pypi"

// canonicalPyPIVersion returns a PyPI version in its PEP 440 canonical form,
// or the version as written when PEP 440 does not describe it.
//
// PyPI treats "1.0.0RC1" and "1.0.0rc1" as one release -- PEP 440 normalizes
// case, separators, and the pre-release spellings, and the index refuses to
// hold both -- so two identities for the pair are two components for one
// package: duplicate matches, duplicate vulnerabilities. The purl
// specification normalizes the pypi *name* (lowercase, "_" to "-"), which
// packageurl-go applies inside Normalize, and says nothing about the version;
// its typeAdjustVersion folds case for huggingface alone. This is the one
// rule the identity layer applies on top of the library, and it is scoped by
// purl type: every Python package-manager token mints pkg:pypi, so the type is
// the complete test.
//
// The grammar is delegated, not transcribed. go-pep440-version owns what a
// PEP 440 version is (epoch, release, pre/post/dev, local) and what its
// canonical rendering looks like; it is the library the grype/syft/trivy tree
// already uses. Hand-writing the grammar would go stale silently, in the
// direction of splitting identities. TestPyPIVersionCanonicalFormMatchesLibrary
// pins the library's answers so an upstream change fails a test here rather
// than moving identities quietly.
//
// A version the library cannot parse is returned exactly as written. That is
// what keeps the rule from corrupting a non-Python version that reaches this
// type by mistake -- "1.0-SNAPSHOT" is refused, not folded -- and what keeps a
// package with an unconventional version in the inventory rather than out of
// it. The parser is third-party code on an untrusted input path, so a panic
// inside it is contained here and treated the same way.
func canonicalPyPIVersion(version string) (canonical string) {
	trimmed := strings.TrimSpace(version)
	if trimmed == "" {
		return version
	}
	canonical = version
	defer func() {
		if recovered := recover(); recovered != nil {
			canonical = version
		}
	}()
	parsed, err := pep440.Parse(trimmed)
	if err != nil {
		return version
	}
	if rendered := parsed.String(); rendered != "" {
		return rendered
	}
	return version
}
