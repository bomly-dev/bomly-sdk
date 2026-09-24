package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-sdk/model"
)

// Decode bounds: dumb bytes and counts, frozen once pinned.
const (
	// MaxRecordBytes bounds one encoded record. A record's packages section
	// is one registry payload and its manifests are a lean projection of one
	// graph, so the model's payload bound covers it.
	MaxRecordBytes = model.MaxPayloadBytes
	// MaxManifests bounds the manifests of one record.
	MaxManifests = 1 << 16
	// MaxFindings bounds the findings of one record.
	MaxFindings = 1 << 20
)

var (
	// ErrRecordTooLarge is returned, wrapped, when a record exceeds a bound.
	ErrRecordTooLarge = errors.New("scan record exceeds the decode bound")
	// ErrSchemaVersion is returned when a record names a schema this package
	// does not read.
	ErrSchemaVersion = errors.New("unsupported scan record schema")
	// ErrDigestMismatch is returned when a section's recorded digest does
	// not match its content.
	ErrDigestMismatch = errors.New("scan record section digest does not match its content")
)

// recordBounds are consulted by Decode; a test shrinks them to exercise a
// refusal without building a payload the size of the real bound.
var recordBounds = struct {
	bytes, manifests, dependencies, packages, findings int
}{MaxRecordBytes, MaxManifests, model.MaxGraphNodes, model.MaxRegistryPackages, MaxFindings}

// Encode writes a record as its canonical bytes. Every collection is sorted
// -- manifests by path, dependencies by ID and their edges by target,
// packages by package URL, findings by ID then package -- and SchemaVersion
// and the section digests are filled, so two records with the same content
// encode to the same bytes. The record passed in is not modified.
func Encode(r *Record) ([]byte, error) {
	if r == nil {
		return nil, errors.New("scan record is nil")
	}
	canonical := canonicalize(*r)
	digests, err := sectionDigests(canonical)
	if err != nil {
		return nil, err
	}
	canonical.Digests = &digests
	return json.Marshal(canonical)
}

// Digest returns "sha256:<hex>" over Encode(r): a content identity for the
// whole record.
func Digest(r *Record) (string, error) {
	data, err := Encode(r)
	if err != nil {
		return "", err
	}
	return digestOf(data), nil
}

// Decode reads a record from its bytes, refusing one over the bounds, of
// another schema version, or whose section digests do not match their
// content. Unknown keys are ignored, so a record written by a later minor
// of the schema still reads.
//
// The byte bound is the memory guard; the count bounds are checked after
// the whole document is decoded, which is cheaper than a streaming reader
// over a nested record and, with the byte bound in front, no less safe.
func Decode(data []byte) (*Record, error) {
	if len(data) > recordBounds.bytes {
		return nil, fmt.Errorf("%w: %d bytes, over %d", ErrRecordTooLarge, len(data), recordBounds.bytes)
	}
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("scan record: %w", err)
	}
	if r.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: %q", ErrSchemaVersion, r.SchemaVersion)
	}
	if len(r.Manifests) > recordBounds.manifests {
		return nil, fmt.Errorf("%w: %d manifests, over %d", ErrRecordTooLarge, len(r.Manifests), recordBounds.manifests)
	}
	for _, manifest := range r.Manifests {
		if len(manifest.Dependencies) > recordBounds.dependencies {
			return nil, fmt.Errorf("%w: manifest %q: %d dependencies, over %d", ErrRecordTooLarge, manifest.Path, len(manifest.Dependencies), recordBounds.dependencies)
		}
	}
	if len(r.Packages) > recordBounds.packages {
		return nil, fmt.Errorf("%w: %d packages, over %d", ErrRecordTooLarge, len(r.Packages), recordBounds.packages)
	}
	if len(r.Findings) > recordBounds.findings {
		return nil, fmt.Errorf("%w: %d findings, over %d", ErrRecordTooLarge, len(r.Findings), recordBounds.findings)
	}
	if r.Digests != nil {
		actual, err := sectionDigests(canonicalize(r))
		if err != nil {
			return nil, err
		}
		for _, section := range []struct{ name, recorded, actual string }{
			{"manifests", r.Digests.Manifests, actual.Manifests},
			{"packages", r.Digests.Packages, actual.Packages},
			{"findings", r.Digests.Findings, actual.Findings},
		} {
			if section.recorded != "" && section.recorded != section.actual {
				return nil, fmt.Errorf("%w: %s", ErrDigestMismatch, section.name)
			}
		}
	}
	return &r, nil
}

// canonicalize returns a shallow copy with every collection in its fixed
// order. Slices are copied before sorting so the caller's record is left as
// it was, and an empty collection becomes nil: the encoder omits an empty
// slice, so a digest over it must be taken over what the encoder writes --
// the fuzzer found a decoded empty section digesting as "[]" while its
// re-encoding carried no key at all.
func canonicalize(r Record) Record {
	r.SchemaVersion = SchemaVersion
	if len(r.Manifests) == 0 {
		r.Manifests = nil
	}
	if len(r.Packages) == 0 {
		r.Packages = nil
	}
	if len(r.Findings) == 0 {
		r.Findings = nil
	}
	if len(r.Warnings) == 0 {
		r.Warnings = nil
	}
	if len(r.Waivers) == 0 {
		r.Waivers = nil
	}
	if len(r.Manifests) > 0 {
		manifests := make([]Manifest, len(r.Manifests))
		copy(manifests, r.Manifests)
		for i := range manifests {
			if len(manifests[i].Dependencies) == 0 {
				continue
			}
			deps := make([]Dependency, len(manifests[i].Dependencies))
			copy(deps, manifests[i].Dependencies)
			for j := range deps {
				deps[j].DependsOn = sortedOrNil(deps[j].DependsOn)
				if len(deps[j].Scopes) == 0 {
					deps[j].Scopes = nil
				}
				if len(deps[j].Locations) == 0 {
					deps[j].Locations = nil
				}
				if len(deps[j].Licenses) == 0 {
					deps[j].Licenses = nil
				}
			}
			sort.SliceStable(deps, func(a, b int) bool { return deps[a].ID < deps[b].ID })
			manifests[i].Dependencies = deps
		}
		sort.SliceStable(manifests, func(a, b int) bool {
			if manifests[a].Path != manifests[b].Path {
				return manifests[a].Path < manifests[b].Path
			}
			return manifests[a].Subproject < manifests[b].Subproject
		})
		r.Manifests = manifests
	}
	if len(r.Packages) > 0 {
		packages := make([]*model.Package, 0, len(r.Packages))
		for _, pkg := range r.Packages {
			if pkg != nil {
				packages = append(packages, pkg)
			}
		}
		sort.SliceStable(packages, func(a, b int) bool { return packages[a].PURL < packages[b].PURL })
		if len(packages) == 0 {
			packages = nil
		}
		r.Packages = packages
	}
	if len(r.Findings) > 0 {
		findings := append([]model.Finding(nil), r.Findings...)
		sort.SliceStable(findings, func(a, b int) bool {
			if findings[a].ID != findings[b].ID {
				return findings[a].ID < findings[b].ID
			}
			return findings[a].PackageRef < findings[b].PackageRef
		})
		r.Findings = findings
	}
	if len(r.Warnings) > 0 {
		warnings := append(r.Warnings[:0:0], r.Warnings...)
		sort.SliceStable(warnings, func(a, b int) bool {
			left := strings.Join([]string{string(warnings[a].Type), string(warnings[a].Code), warnings[a].Source, warnings[a].Subproject, warnings[a].Manifest, warnings[a].Message}, "\x00")
			right := strings.Join([]string{string(warnings[b].Type), string(warnings[b].Code), warnings[b].Source, warnings[b].Subproject, warnings[b].Manifest, warnings[b].Message}, "\x00")
			return left < right
		})
		r.Warnings = warnings
	}
	if len(r.Waivers) > 0 {
		waivers := append([]Waiver(nil), r.Waivers...)
		sort.SliceStable(waivers, func(a, b int) bool { return waivers[a].ID < waivers[b].ID })
		r.Waivers = waivers
	}
	return r
}

// sectionDigests digests each section's canonical encoding. An absent
// section digests as the encoding of null, so a record with no findings has
// a findings digest a reader can still compare.
func sectionDigests(r Record) (SectionDigests, error) {
	var out SectionDigests
	for _, section := range []struct {
		value any
		into  *string
	}{{r.Manifests, &out.Manifests}, {r.Packages, &out.Packages}, {r.Findings, &out.Findings}} {
		data, err := json.Marshal(section.value)
		if err != nil {
			return out, err
		}
		*section.into = digestOf(data)
	}
	return out, nil
}

// sortedOrNil returns a sorted copy, or nil for an empty list, so an empty
// list and an absent one digest the same way they encode: absent.
func sortedOrNil(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
