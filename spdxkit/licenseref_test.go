package spdxkit

import (
	"regexp"
	"testing"
)

var idstringPattern = regexp.MustCompile(`^LicenseRef-[A-Za-z0-9.-]+$`)

func TestMintLicenseRefDeterminismAndCharset(t *testing.T) {
	first := MintLicenseRef("see LICENSE file")
	second := MintLicenseRef("see LICENSE file")
	if first.RefID != second.RefID {
		t.Fatalf("minting is not deterministic: %q vs %q", first.RefID, second.RefID)
	}
	if !idstringPattern.MatchString(first.RefID) {
		t.Fatalf("RefID %q violates the SPDX idstring charset", first.RefID)
	}
	if first.Text != "see LICENSE file" {
		t.Fatalf("Text mutated: %q", first.Text)
	}
}

func TestMintLicenseRefFoldsWhitespaceOnly(t *testing.T) {
	a := MintLicenseRef("see  LICENSE\n\tfile")
	b := MintLicenseRef("see LICENSE file")
	if a.RefID != b.RefID {
		t.Fatalf("whitespace variants mint different refs: %q vs %q", a.RefID, b.RefID)
	}
	if a.Text != "see  LICENSE\n\tfile" {
		t.Fatalf("original text not preserved: %q", a.Text)
	}
}

func TestMintLicenseRefDistinctTexts(t *testing.T) {
	if MintLicenseRef("text one").RefID == MintLicenseRef("text two").RefID {
		t.Fatal("distinct texts minted the same reference")
	}
}

func TestExtractedTextValid(t *testing.T) {
	minted := MintLicenseRef("see LICENSE file")
	if !minted.Valid() {
		t.Fatal("freshly minted value reports invalid")
	}
	tampered := ExtractedText{RefID: minted.RefID, Text: "different text"}
	if tampered.Valid() {
		t.Fatal("tampered value reports valid — Text is authoritative")
	}
	if (ExtractedText{RefID: "LicenseRef-bomly-not-a-hash", Text: "see LICENSE file"}).Valid() {
		t.Fatal("hand-authored reference reports valid")
	}
}
