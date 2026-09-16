package sbom

import (
	"strings"

	"github.com/bomly-dev/bomly-sdk/purlkit"

	"github.com/bomly-dev/bomly-sdk/model"
)

// parsePURL delegates to purlkit, the SDK's kit over the official
// packageurl-go. sdk.ParsePackageURL was the deprecated anchore-fork entry
// point and is gone; the nil-on-failure shape is kept for callers.
func parsePURL(value string) *purlkit.PURL {
	parsed, err := purlkit.Parse(strings.TrimSpace(value))
	if err != nil {
		return nil
	}
	return &parsed
}

// purlTypeEcosystems inverts model.PackageURLTypeForValues for the purl types
// whose spec name differs from the Bomly ecosystem name. Without these, a PURL
// Bomly itself emitted would not round-trip through SBOM ingest: ParseEcosystem
// only knows Bomly's own identifiers.
//
// Types that two ecosystems share are deliberately absent. pkg:hex is emitted
// for both Elixir (mix) and Erlang (rebar), and nothing in the PURL says which;
// since the standard codecs do not carry Component.Ecosystem — CycloneDX drops
// it and SPDX rebuilds it from the PURL — guessing here would relabel every
// round-tripped Erlang dependency as Elixir, and packageManagerForPURLType
// would then call it Mix. Leaving it unknown keeps the ambiguity visible.
// The purl-type -> ecosystem question is the SDK's, answered by
// EcosystemForPURLType. It was reassembled here out of purlkit calls plus a
// fallback of this package's own, which is the same drift in a thinner
// disguise: the SDK grew a second lookup for manager-name aliases and this
// copy did not, so "swiftpm" resolved to unknown here and to swift there.
// Delegating picked that up rather than any change being made for it.
func ecosystemFromPURLType(purlType string) model.Ecosystem {
	return model.EcosystemForPURLType(purlType)
}

// ComponentEcosystem resolves the ecosystem a document component belongs to:
// the component's own ecosystem field when the SDK recognizes it, and
// otherwise the ecosystem named by its package URL's type.
//
// It lives here, beside the other ingest identity rules, because the question
// is about Component -- this package's own type -- and because it used to be
// answered in more than one place. ToGraph resolved it inline, and the CLI's
// benchmark kept a twelve-row purl-type switch of its own that had already
// drifted away from the SDK's table: it answered Elixir for pkg:hex, which
// purlkit refuses precisely because Hex serves Elixir and Erlang alike and
// nothing in the PURL says which; and it had never learned hackage, cran,
// opam, deb, or otp, so Haskell, R, OCaml, Debian, and OTP components came
// back unknown. That is what a second table does -- it is correct the day it
// is written and quietly wrong afterwards.
//
// The purl-type half of the answer is model.EcosystemForPURLType, the one table
// every consumer reads; this function adds only the component's own
// ecosystem hint on top of it.
func ComponentEcosystem(component Component) model.Ecosystem {
	if ecosystem, ok := parseEcosystemHint(component.Ecosystem); ok {
		return ecosystem
	}
	if purl := parsePURL(component.PURL); purl != nil {
		return ecosystemFromPURLType(purl.Type)
	}
	return model.EcosystemUnknown
}

func packageManagerForPURL(value string, ecosystemHint, packageManagerHint string) model.PackageManager {
	if manager, ok := parsePackageManagerHint(packageManagerHint); ok {
		return manager
	}
	if purl := parsePURL(value); purl != nil {
		if manager, ok := packageManagerForPURLType(purl.Type); ok {
			return manager
		}
	}
	if ecosystem, ok := parseEcosystemHint(ecosystemHint); ok {
		if manager, ok := preferredPackageManagerForEcosystem(ecosystem); ok {
			return manager
		}
	}
	return model.PackageManagerUnknown
}

func packageManagerForPURLType(purlType string) (model.PackageManager, bool) {
	ecosystem := ecosystemFromPURLType(purlType)
	if ecosystem == model.EcosystemUnknown {
		return model.PackageManagerUnknown, false
	}
	manager, ok := preferredPackageManagerForEcosystem(ecosystem)
	return manager, ok
}

func preferredPackageManagerForEcosystem(ecosystem model.Ecosystem) (model.PackageManager, bool) {
	for _, manager := range model.AllPackageManagers() {
		if manager.Ecosystem() == ecosystem {
			return manager, true
		}
	}
	return model.PackageManagerUnknown, false
}

func parsePackageManagerHint(value string) (model.PackageManager, bool) {
	manager, err := model.ParsePackageManager(value)
	if err != nil {
		return model.PackageManagerUnknown, false
	}
	return manager, true
}

func parseEcosystemHint(value string) (model.Ecosystem, bool) {
	ecosystem, err := model.ParseEcosystem(value)
	if err != nil {
		return model.EcosystemUnknown, false
	}
	return ecosystem, true
}
