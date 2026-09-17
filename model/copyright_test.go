package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeCopyright(t *testing.T) {
	if got := NormalizeCopyright("  Copyright (c) 2024 Acme  "); got != "Copyright (c) 2024 Acme" {
		t.Fatalf("NormalizeCopyright trimmed to %q", got)
	}
	// A notice naming several holders is one per line, and that structure is
	// part of the claim.
	multi := "Copyright (c) 2020 Alice\nCopyright (c) 2021 Bob\tand contributors"
	if got := NormalizeCopyright(multi); got != multi {
		t.Fatalf("NormalizeCopyright damaged line structure: %q", got)
	}
	// Other control characters came from a malformed document; an escape
	// sequence would otherwise reach the terminal that renders the notice.
	if got := NormalizeCopyright("Copyright\x00 Acme\x1b[31m"); got != "Copyright Acme[31m" {
		t.Fatalf("NormalizeCopyright = %q, want the control characters dropped", got)
	}
	// Over-long input yields nothing rather than a notice with holders cut off.
	if got := NormalizeCopyright(strings.Repeat("a", maxCopyrightLength+1)); got != "" {
		t.Fatalf("an over-long copyright survived as %d bytes", len(got))
	}
	if got := NormalizeCopyright(strings.Repeat("a", maxCopyrightLength)); len(got) != maxCopyrightLength {
		t.Fatalf("a copyright at the bound was not kept whole: %d bytes", len(got))
	}
	// The repair that amplified descriptions past their bound (#58) is the
	// same loop, so the same reproducer is refused here on the first pass.
	if got := NormalizeCopyright("00" + strings.Repeat("\xff", 3000) + "0000"); got != "" {
		t.Fatalf("a value that repairs past the bound was kept at %d bytes", len(got))
	}
	for _, blank := range []string{"", "   ", "\x00\x07"} {
		if got := NormalizeCopyright(blank); got != "" {
			t.Fatalf("NormalizeCopyright(%q) = %q, want empty", blank, got)
		}
	}
}

// TestCopyrightWireIsGatedBothWays pins the codec: a plugin is an untrusted
// producer, and a node built in process never passed a decoder, so the gate
// runs on the way in and on the way out.
func TestCopyrightWireIsGatedBothWays(t *testing.T) {
	payload := `{"nodes":[{"kind":"dependency","id":"pkg:npm/react@18.2.0","purl":"pkg:npm/react@18.2.0",` +
		`"copyright":"Copyright\u0007 Meta\nAll rights reserved"}]}`
	var decoded Graph
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("decode graph: %v", err)
	}
	if got := decoded.DependencyNodes()[0].Copyright; got != "Copyright Meta\nAll rights reserved" {
		t.Fatalf("decoded copyright = %q, want the control character dropped and the line break kept", got)
	}

	graph := New()
	node := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "react", Version: "18.2.0"})
	node.Copyright = strings.Repeat("c", maxCopyrightLength+1)
	if err := graph.AddNode(node); err != nil {
		t.Fatalf("add node: %v", err)
	}
	encoded, err := json.Marshal(graph)
	if err != nil {
		t.Fatalf("encode graph: %v", err)
	}
	if strings.Contains(string(encoded), `"copyright"`) {
		t.Fatalf("an over-long copyright reached the wire: %d bytes encoded", len(encoded))
	}
}

// TestCopyrightFoldGatesBothWitnesses pins the ordering the other fill-gaps
// assertions follow: an unpublishable survivor must not block a valid
// incoming notice.
func TestCopyrightFoldGatesBothWitnesses(t *testing.T) {
	graph := New()
	first := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "react", Version: "18.2.0"})
	first.Copyright = strings.Repeat("c", maxCopyrightLength+1)
	if err := graph.AddNode(first); err != nil {
		t.Fatalf("add first: %v", err)
	}
	second := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "react", Version: "18.2.0"})
	second.Copyright = "Copyright\x07 Meta"
	if _, err := graph.InsertNode(second); err != nil {
		t.Fatalf("insert second: %v", err)
	}
	if got := graph.DependencyNodes()[0].Copyright; got != "Copyright Meta" {
		t.Fatalf("folded copyright = %q, want the valid witness, gated", got)
	}
}

// TestPackageCopyrightIsGated covers the registry side: the merge, the
// normalization hook every registry entry passes, the codec, and seeding a
// package from a node.
func TestPackageCopyrightIsGated(t *testing.T) {
	dst := &Package{Copyright: strings.Repeat("c", maxCopyrightLength+1)}
	dst.MergeFrom(&Package{Copyright: "Copyright\x00 Acme"})
	if dst.Copyright != "Copyright Acme" {
		t.Fatalf("merged copyright = %q, want the valid update, gated, to win over the unpublishable value", dst.Copyright)
	}

	pkg := Package{Copyright: "Copyright\x1b Acme"}
	pkg.NormalizeAssertions()
	if pkg.Copyright != "Copyright Acme" {
		t.Fatalf("normalized copyright = %q, want the control character dropped", pkg.Copyright)
	}

	encoded, err := json.Marshal(Package{Copyright: strings.Repeat("c", maxCopyrightLength+1)})
	if err != nil {
		t.Fatalf("encode package: %v", err)
	}
	if strings.Contains(string(encoded), `"copyright"`) {
		t.Fatalf("an over-long copyright reached the wire through Package")
	}

	dep := mustDep(t, Coordinates{Ecosystem: EcosystemNPM, Name: "react", Version: "18.2.0"})
	dep.Copyright = "Copyright\x07 Meta"
	if seeded := PackageFromDependencyNode(dep); seeded == nil || seeded.Copyright != "Copyright Meta" {
		t.Fatalf("seeded package = %+v, want the gated copyright", seeded)
	}
}
