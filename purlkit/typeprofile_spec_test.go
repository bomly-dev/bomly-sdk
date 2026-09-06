package purlkit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// specTypeDefinition is the slice of a purl-spec type definition document
// that states structural requirements. Fields the table does not act on are
// ignored rather than removed from the vendored files: the files stay
// verbatim so a future rule category is visible to whoever looks next.
type specTypeDefinition struct {
	Type                string `json:"type"`
	NamespaceDefinition struct {
		Requirement string `json:"requirement"`
	} `json:"namespace_definition"`
	QualifiersDefinition []struct {
		Key         string `json:"key"`
		Requirement string `json:"requirement"`
	} `json:"qualifiers_definition"`
}

// specProfile is a type definition reduced to the same shape as typeProfile,
// so the two can be compared directly.
type specProfile struct {
	namespaceRequired   bool
	namespaceProhibited bool
	requiredQualifiers  []string
}

// libraryEnforced names the rules packageurl-go applies itself, which is why
// typeProfiles omits them. Keeping the list here rather than in the table
// keeps the diff honest: the specification requires these, and something
// enforces them — just not this table.
//
// Read from the library's behavior, not from its source: each entry is
// proven by the assertion in TestLibraryEnforcedRulesStillHold below, so a
// library release that stops enforcing a rule fails a test here instead of
// opening a hole nothing covers.
var libraryEnforced = map[string]specProfile{
	"chrome-extension": {namespaceProhibited: true},
	"julia":            {namespaceProhibited: true, requiredQualifiers: []string{"uuid"}},
	"otp":              {namespaceProhibited: true},
	"vcpkg":            {namespaceProhibited: true},
	"swift":            {namespaceRequired: true},
	"vscode-extension": {namespaceRequired: true},
}

// loadSpecProfiles reads the vendored purl specification type definitions.
func loadSpecProfiles(t *testing.T) map[string]specProfile {
	t.Helper()
	dir := filepath.Join("testdata", "purl-spec", "types")
	entries, err := filepath.Glob(filepath.Join(dir, "*-definition.json"))
	if err != nil {
		t.Fatalf("glob %s: %v", dir, err)
	}
	if len(entries) == 0 {
		t.Fatalf("no vendored type definitions in %s; run scripts/vendor-purl-spec.sh", dir)
	}
	profiles := make(map[string]specProfile, len(entries))
	for _, entry := range entries {
		raw, err := os.ReadFile(entry)
		if err != nil {
			t.Fatalf("read %s: %v", entry, err)
		}
		var definition specTypeDefinition
		if err := json.Unmarshal(raw, &definition); err != nil {
			t.Fatalf("parse %s: %v", entry, err)
		}
		if definition.Type == "" {
			t.Fatalf("%s states no type", entry)
		}
		profile := specProfile{}
		switch definition.NamespaceDefinition.Requirement {
		case "required":
			profile.namespaceRequired = true
		case "prohibited":
			profile.namespaceProhibited = true
		case "optional", "":
			// Nothing to enforce.
		default:
			t.Fatalf("%s states an unknown namespace requirement %q — the "+
				"specification grew a value this diff does not understand",
				entry, definition.NamespaceDefinition.Requirement)
		}
		for _, qualifier := range definition.QualifiersDefinition {
			if qualifier.Requirement == "required" {
				profile.requiredQualifiers = append(profile.requiredQualifiers, qualifier.Key)
			}
		}
		sort.Strings(profile.requiredQualifiers)
		profiles[definition.Type] = profile
	}
	return profiles
}

// describe renders a profile as a stable string, for a failure message that
// says what differs rather than dumping two structs.
func (p specProfile) describe() string {
	var parts []string
	if p.namespaceRequired {
		parts = append(parts, "namespace required")
	}
	if p.namespaceProhibited {
		parts = append(parts, "namespace prohibited")
	}
	if len(p.requiredQualifiers) > 0 {
		parts = append(parts, "required qualifiers "+strings.Join(p.requiredQualifiers, ","))
	}
	if len(parts) == 0 {
		return "no structural rules"
	}
	return strings.Join(parts, "; ")
}

// enforcedProfile is the rule set purlkit actually applies for a type:
// this package's table plus what the library enforces on its own.
func enforcedProfile(purlType string) specProfile {
	profile := specProfile{}
	if row, ok := typeProfiles[purlType]; ok {
		profile.namespaceRequired = row.namespaceRequired
		profile.namespaceProhibited = row.namespaceProhibited
		profile.requiredQualifiers = append(profile.requiredQualifiers, row.requiredQualifiers...)
	}
	if row, ok := libraryEnforced[purlType]; ok {
		profile.namespaceRequired = profile.namespaceRequired || row.namespaceRequired
		profile.namespaceProhibited = profile.namespaceProhibited || row.namespaceProhibited
		profile.requiredQualifiers = append(profile.requiredQualifiers, row.requiredQualifiers...)
	}
	sort.Strings(profile.requiredQualifiers)
	return profile
}

// TestTypeProfilesMatchSpecification is the guard the hand-written table
// needs, and the reason the specification documents are vendored: a table
// transcribed from a specification is correct the day it is written and
// silently wrong the day the specification moves. Every difference between
// what the specification states and what purlkit enforces must be named in
// specDeviations, with a reason, or this fails.
func TestTypeProfilesMatchSpecification(t *testing.T) {
	spec := loadSpecProfiles(t)
	seenDeviation := map[string]bool{}

	types := make([]string, 0, len(spec))
	for purlType := range spec {
		types = append(types, purlType)
	}
	sort.Strings(types)

	for _, purlType := range types {
		want := spec[purlType]
		got := enforcedProfile(purlType)
		if want.describe() == got.describe() {
			if _, ok := specDeviations[purlType]; ok {
				t.Errorf("specDeviations names %q, but purlkit and the specification agree (%s); "+
					"drop the entry", purlType, want.describe())
			}
			continue
		}
		reason, ok := specDeviations[purlType]
		if !ok {
			t.Errorf("type %q: specification states %s, purlkit enforces %s; "+
				"fix typeProfiles or record the departure in specDeviations",
				purlType, want.describe(), got.describe())
			continue
		}
		seenDeviation[purlType] = true
		if strings.TrimSpace(reason) == "" {
			t.Errorf("specDeviations[%q] states no reason", purlType)
		}
	}

	for purlType := range specDeviations {
		if seenDeviation[purlType] {
			continue
		}
		if _, ok := spec[purlType]; !ok {
			t.Errorf("specDeviations names %q, which the vendored specification does not define", purlType)
		}
	}

	// A table row for a type the specification does not define is a typo or
	// a stale row: Validate would enforce a rule with no authority behind it.
	for purlType := range typeProfiles {
		if _, ok := spec[purlType]; !ok {
			t.Errorf("typeProfiles has a row for %q, which the vendored specification does not define", purlType)
		}
	}
}

// TestTypeProfilesOmitLibraryEnforcedRules keeps the table's stated
// division of labour true: a row duplicated from the library is a second
// copy of a rule, and the two drift.
func TestTypeProfilesOmitLibraryEnforcedRules(t *testing.T) {
	for purlType := range libraryEnforced {
		if _, ok := typeProfiles[purlType]; ok {
			t.Errorf("typeProfiles duplicates the library's rule for %q", purlType)
		}
	}
}

// TestLibraryEnforcedRulesStillHold proves each libraryEnforced claim
// against the library rather than against its source, so the diff above
// cannot credit packageurl-go with a rule it no longer applies.
func TestLibraryEnforcedRulesStillHold(t *testing.T) {
	cases := map[string]string{
		// Namespace prohibited: a namespace must be rejected.
		"chrome-extension": "pkg:chrome-extension/vendor/abcdefghijklmnopqrstuvwxyzabcdef@1.0",
		"julia":            "pkg:julia/ns/Example@1.0?uuid=7876af07-990d-54b4-ab0e-23690620f79a",
		"otp":              "pkg:otp/ns/cowboy@2.9.0",
		"vcpkg":            "pkg:vcpkg/ns/zlib@1.2.11",
		// Namespace required: its absence must be rejected.
		"swift":            "pkg:swift/swift-numerics@1.0.0",
		"vscode-extension": "pkg:vscode-extension/redhat.java@1.0.0",
	}
	for purlType, value := range cases {
		if _, ok := libraryEnforced[purlType]; !ok {
			t.Fatalf("case for %q is not in libraryEnforced", purlType)
		}
		if _, ok := typeProfiles[purlType]; ok {
			t.Fatalf("case for %q is covered by typeProfiles, so it proves nothing about the library", purlType)
		}
		if err := ValidateString(value); err == nil {
			t.Errorf("ValidateString(%q) = nil: packageurl-go no longer enforces the %q rule "+
				"purlkit credits it with; add the row to typeProfiles", value, purlType)
		}
	}
	for purlType := range libraryEnforced {
		if _, ok := cases[purlType]; !ok {
			t.Errorf("libraryEnforced credits the library with a rule for %q that nothing here proves", purlType)
		}
	}
	// julia's required uuid qualifier, separately from its namespace rule.
	if err := ValidateString("pkg:julia/Example@1.0"); err == nil {
		t.Error(`ValidateString("pkg:julia/Example@1.0") = nil: packageurl-go no longer requires julia's uuid qualifier`)
	}
}
