package sbom

import (
	"testing"

	"github.com/bomly-dev/bomly-sdk/model"
)

// The rows below are the ones a second, hand-written purl-type table gets
// wrong. internal/benchmark used to carry such a table; it answered Elixir for
// pkg:hex and unknown for five whole ecosystems, because the day it was
// written those rows had not been needed yet. Delegating to purlkit is what
// makes these answers arrive without anyone having to remember them.
func TestComponentEcosystemAnswersTheTypesASecondTableForgot(t *testing.T) {
	cases := []struct {
		purl string
		want model.Ecosystem
	}{
		// Types whose spec name differs from the Bomly ecosystem token. Every
		// one of these was absent from the deleted switch.
		{"pkg:hackage/aeson@2.1.0.0", model.EcosystemHaskell},
		{"pkg:cran/ggplot2@3.4.0", model.EcosystemR},
		{"pkg:opam/lwt@5.6.1", model.EcosystemOCaml},
		{"pkg:deb/debian/curl@7.88.1", model.EcosystemDPKG},
		{"pkg:otp/mnesia@4.21", model.EcosystemErlang},

		// Types the deleted switch did know, kept so a regression in the
		// delegation is visible here and not only in the new rows.
		{"pkg:golang/github.com/spf13/cobra@v1.8.0", model.EcosystemGo},
		{"pkg:pypi/requests@2.31.0", model.EcosystemPython},
		{"pkg:gem/rails@7.0.4", model.EcosystemRuby},
		{"pkg:cargo/serde@1.0.0", model.EcosystemRust},

		// Types that are already Bomly ecosystem tokens resolve through the
		// alias table rather than the differing-name table.
		{"pkg:npm/lodash@4.17.21", model.EcosystemNPM},
		{"pkg:apk/alpine/musl@1.2.3", model.EcosystemAPK},

		// pkg:hex is refused on purpose: the Hex registry serves both Elixir
		// and Erlang and nothing in the PURL says which. The deleted switch
		// guessed Elixir, which relabels every Erlang package it sees.
		{"pkg:hex/plug@1.14.0", model.EcosystemUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.purl, func(t *testing.T) {
			got := ComponentEcosystem(Component{PURL: tc.purl})
			if got != tc.want {
				t.Fatalf("ComponentEcosystem(%q) = %q, want %q", tc.purl, got, tc.want)
			}
		})
	}
}

// The component's own ecosystem field is the more authoritative answer when
// the SDK recognizes it, because it is what the producer asserted rather than
// what a purl type implies. A value the SDK does not recognize is not an
// assertion Bomly can act on, so the PURL decides instead.
func TestComponentEcosystemPrefersTheStatedEcosystem(t *testing.T) {
	stated := ComponentEcosystem(Component{Ecosystem: "scala", PURL: "pkg:maven/org.example/lib@1.0"})
	if stated != model.EcosystemScala {
		t.Fatalf("stated ecosystem = %q, want %q", stated, model.EcosystemScala)
	}

	// "flutter" is not an SDK ecosystem; falling through to the PURL is what
	// keeps an unvalidated free-text field out of a typed one.
	unrecognized := ComponentEcosystem(Component{Ecosystem: "flutter", PURL: "pkg:pub/http@1.1.0"})
	if unrecognized != model.EcosystemDart {
		t.Fatalf("unrecognized ecosystem fell back to %q, want %q", unrecognized, model.EcosystemDart)
	}

	if empty := ComponentEcosystem(Component{}); empty != model.EcosystemUnknown {
		t.Fatalf("bare component = %q, want %q", empty, model.EcosystemUnknown)
	}
	if broken := ComponentEcosystem(Component{PURL: "not a package url"}); broken != model.EcosystemUnknown {
		t.Fatalf("malformed PURL = %q, want %q", broken, model.EcosystemUnknown)
	}
}
