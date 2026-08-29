package sdk

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-sdk/identitykit"
)

// IdentityFinalization reports what FinalizeGraphIdentity changed.
type IdentityFinalization struct {
	// Renames maps each entry's original node IDs to their finalized IDs,
	// index-aligned with the container's Entries; entries with no renames
	// hold nil. Callers refresh stored references — manifest root IDs in
	// particular — through these maps. They are per entry because one
	// canonical identity can finalize to different occurrence IDs in
	// different entries.
	Renames []map[string]string
}

// finalizeRecord is one node mid-finalization: its normalized working clone
// plus the identity facts derived in the first pass.
type finalizeRecord struct {
	node       *Dependency
	originalID string
	base       string
	key        string
}

// FinalizeGraphIdentity is the single identity rewrite entry point
// (ADR-0036): it normalizes every node, re-derives every readable ID from
// the identity facets, assigns durable occurrence facets exactly to the
// records established as contradicting, and folds or replaces every
// ephemeral insertion discriminator. It runs over the whole container
// because contradiction is scan-global: the same origin gets the same
// finalized ID in every entry, so a later graph merge folds exactly the
// witnesses of one resolution.
//
// Per contested identity: the project's own record keeps the canonical
// unsuffixed ID and carries the first-party sentinel facet; an external
// record whose admitted origin facet is unique gets the facet-hash suffix;
// records distinguishable only by raw evidence — and records whose admitted
// facets coincide after identity normalization — get run-local ordinals,
// assigned per distinct resolution key in lexicographic key order (records
// sharing a key are witnesses of one resolution and fold, which is why
// record-level ties cannot arise); a record with no resolution evidence
// keeps the unsuffixed ID as the "resolution unknown" occurrence. Raw
// evidence never reaches an ID, a facet, or an address.
//
// The container is mutated in place. Finalization is idempotent: a second
// call is a no-op. Finalize before materializing or serializing output —
// GraphContainer.ConsolidatedGraph returns the single-entry graph by
// reference, so consumers observe finalized records only after this ran.
func FinalizeGraphIdentity(container *GraphContainer) (*IdentityFinalization, error) {
	result := &IdentityFinalization{}
	if container == nil {
		return result, nil
	}
	result.Renames = make([]map[string]string, len(container.Entries))

	// Pass 1: normalize working clones, derive each record's base and
	// resolution key, and collect the scan-global key and facet sets.
	perEntry := make([][]finalizeRecord, len(container.Entries))
	distinctKeys := make(map[string]map[string]struct{})
	facetOfKey := make(map[string]map[string]string) // base -> key -> admitted facet ("" = none)
	keysOfFacet := make(map[string]map[string]int)   // base -> facet -> distinct-key count
	for i := range container.Entries {
		entry := &container.Entries[i]
		if entry.Graph == nil {
			continue
		}
		records := make([]finalizeRecord, 0, entry.Graph.Size())
		for _, node := range entry.Graph.Nodes() {
			if node == nil {
				continue
			}
			clone := node.Clone()
			NormalizeDependencyIdentity(clone)
			if canonical := clone.CanonicalPURL(); canonical != "" {
				clone.PURL = canonical
			}
			base := clone.Coordinates.PackageIdentity()
			if base == "" {
				// A node carrying no identity fields keeps its supplied ID as
				// the base — with any ephemeral discriminator and any
				// occurrence suffix from a previous finalization stripped, so
				// re-finalizing derives the same base and stays idempotent.
				base = identityFallbackBase(clone.ID)
			}
			if base == "" {
				return nil, fmt.Errorf("finalize identity: dependency %q has no canonical identity", node.QualifiedName())
			}
			key := resolutionKey(clone)
			if key != "" {
				if distinctKeys[base] == nil {
					distinctKeys[base] = make(map[string]struct{})
					facetOfKey[base] = make(map[string]string)
					keysOfFacet[base] = make(map[string]int)
				}
				if _, seen := distinctKeys[base][key]; !seen {
					distinctKeys[base][key] = struct{}{}
					facet := ""
					if !clone.ProjectOwned() {
						if admitted, ok := identityOriginFacet(clone.Origin); ok {
							facet = admitted
						}
					}
					facetOfKey[base][key] = facet
					if facet != "" {
						keysOfFacet[base][facet]++
					}
				}
			}
			records = append(records, finalizeRecord{node: clone, originalID: node.ID, base: base, key: key})
		}
		perEntry[i] = records
	}

	// Ordinals are a pure function of the scan's evidence: per base, every
	// key without a unique admitted facet is ordered lexicographically and
	// numbered from 1, so identical evidence yields identical IDs on every
	// machine and every run.
	ordinalOfKey := make(map[string]map[string]int, len(distinctKeys))
	for base, keys := range distinctKeys {
		if len(keys) < 2 {
			continue
		}
		var ordinalKeys []string
		for key := range keys {
			facet := facetOfKey[base][key]
			if key == resolutionKeyFirstParty {
				continue
			}
			if facet != "" && keysOfFacet[base][facet] == 1 {
				continue
			}
			ordinalKeys = append(ordinalKeys, key)
		}
		sort.Strings(ordinalKeys)
		ordinals := make(map[string]int, len(ordinalKeys))
		for i, key := range ordinalKeys {
			ordinals[key] = i + 1
		}
		ordinalOfKey[base] = ordinals
	}

	// Pass 2: rebuild each entry's graph under finalized IDs, folding the
	// records that finalize to one ID, then remap the edges.
	for i := range container.Entries {
		entry := &container.Entries[i]
		if entry.Graph == nil {
			continue
		}
		finalized := NewWithCapacity(len(perEntry[i]))
		idMapping := make(map[string]string, len(perEntry[i]))
		for _, record := range perEntry[i] {
			finalID, facet := finalizeIdentity(record, distinctKeys, facetOfKey, keysOfFacet, ordinalOfKey)
			if identitykit.IsEphemeralID(finalID) {
				return nil, fmt.Errorf("finalize identity: %q would survive with an ephemeral discriminator", record.base)
			}
			record.node.ID = finalID
			record.node.occurrenceFacet = facet
			if survivor, taken := finalized.Node(finalID); taken {
				foldWitness(survivor, record.node)
			} else if err := finalized.AddNode(record.node); err != nil {
				return nil, fmt.Errorf("finalize identity: add %q: %w", finalID, err)
			}
			idMapping[record.originalID] = finalID
			if record.originalID != finalID {
				if result.Renames[i] == nil {
					result.Renames[i] = make(map[string]string)
				}
				result.Renames[i][record.originalID] = finalID
			}
		}
		var edgeErr error
		entry.Graph.WalkEdges(func(from, to *Dependency) bool {
			if from == nil || to == nil {
				return true
			}
			fromID, toID := idMapping[from.ID], idMapping[to.ID]
			if fromID == "" || toID == "" || fromID == toID {
				return true
			}
			if err := finalized.AddEdge(fromID, toID); err != nil {
				edgeErr = fmt.Errorf("finalize identity: edge %q -> %q: %w", fromID, toID, err)
				return false
			}
			return true
		})
		if edgeErr != nil {
			return nil, edgeErr
		}
		entry.Graph = finalized
	}
	return result, nil
}

// finalizeIdentity derives one record's finalized readable ID and durable
// occurrence facet from the scan-global identity facts.
func finalizeIdentity(record finalizeRecord, distinctKeys map[string]map[string]struct{}, facetOfKey map[string]map[string]string, keysOfFacet map[string]map[string]int, ordinalOfKey map[string]map[string]int) (string, string) {
	contested := len(distinctKeys[record.base]) >= 2
	if !contested || record.key == "" {
		// Uncontested identities and evidence-free witnesses keep the plain
		// base and the default (empty) facet; a gap witness folds into
		// whichever record holds the base.
		return record.base, ""
	}
	if record.node.ProjectOwned() {
		// The canonical slot belongs to the project's own record: no suffix,
		// but the sentinel facet enters its content address.
		return record.base, FirstPartyOccurrenceFacet
	}
	facet := facetOfKey[record.base][record.key]
	if facet != "" && keysOfFacet[record.base][facet] == 1 {
		return identitykit.JoinID(record.base, identitykit.OccurrenceSuffix(facet)), facet
	}
	// Raw-evidence-only records carry no facet; records whose admitted
	// facets coincide keep the shared facet — and therefore share a content
	// address — while the ordinal keeps their readable IDs apart.
	ordinal := ordinalOfKey[record.base][record.key]
	return identitykit.JoinID(record.base, identitykit.OrdinalSuffix(ordinal)), facet
}

// foldWitness merges one witness of a resolution into the surviving node.
// Usage facts aggregate — scope, relationship, and locations describe how
// and where the package is used, and every witness contributes — while
// origin and the occurrence facet fill only a gap: the records witness one
// resolution, so there is nothing to reconcile.
func foldWitness(surviving, witness *Dependency) {
	surviving.Relationship = MergeDependencyRelationship(surviving.Relationship, witness.Relationship)
	for _, scope := range witness.Scopes {
		surviving.AddScope(scope)
	}
	mergeDependencyLocations(surviving, witness.Locations)
	if surviving.Origin.Empty() && !witness.Origin.Empty() {
		surviving.Origin = witness.Origin
	}
	if surviving.occurrenceFacet == "" {
		surviving.occurrenceFacet = witness.occurrenceFacet
	}
	// Ownership is a positive assertion: when any folded witness is the
	// project's own record, the survivor is too — otherwise a gap witness
	// that happened to sort first would strip the first-party marker and
	// reopen the survivor to external enrichment.
	if witness.FirstParty {
		surviving.FirstParty = true
	}
}

// identityFallbackBase derives the readable base for a node with no
// derivable package identity: its supplied ID with any ephemeral
// discriminator and any occurrence suffix from a previous finalization
// stripped.
func identityFallbackBase(id string) string {
	base, _ := identitykit.SplitID(identitykit.EphemeralBase(id))
	return strings.TrimSpace(base)
}
