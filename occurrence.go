package sdk

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/bomly-dev/bomly-sdk/identitykit"
)

// ProjectOwned reports whether the node is the scanned project's own record —
// its root package, a workspace member, a reactor module — rather than a
// consumed third-party package. Ownership is the FirstParty marker, never
// the package type (the NodeIsEnrichable rule): an application-typed
// component imported from an SBOM is an artifact kind, not proof it belongs
// to the scanned project, and two such imports with contradicting
// resolutions must stay distinct occurrences instead of folding under a
// shared first-party key. Detectors mark the nodes they synthesize for the
// build itself. Identity finalization exempts project-owned records from
// external occurrence suffixes, and their resolution is the local source
// tree no matter what origin metadata a producer stapled on.
func (d *Dependency) ProjectOwned() bool {
	return d != nil && d.FirstParty
}

// Resolution keys are domain-separated: each variant carries its own tag,
// so a raw resolution string that happens to spell the sentinel or an
// origin key's NUL-joined form cannot collide with the structured
// variants. No tag is a prefix of another, and the tagged content follows
// it, so the key space is injective per domain.
const (
	resolutionKeyFirstParty = "first-party\x00"
	resolutionKeyOriginTag  = "origin\x00"
	resolutionKeyRawTag     = "raw\x00"
)

// resolutionKey identifies which resolution a record witnesses, for
// contradiction detection only: the first-party sentinel for project-owned
// records, else the ADR-0033-normalized origin, else the manifest's raw
// resolution string — each under its domain tag. Raw evidence is legal
// here — comparison never publishes — but it must never reach a readable
// ID, a facet, or a content address; the identity admission rule
// (identityOriginFacet) is the separate gate for what persists.
func resolutionKey(node *Dependency) string {
	if node == nil {
		return ""
	}
	if node.ProjectOwned() {
		// Project-ownedness comes before the origin key: an external record
		// asserting the same origin must not read as the same resolution and
		// fold away the project record's suppression semantics.
		return resolutionKeyFirstParty
	}
	if key := originKey(node.Origin); key != "" {
		return resolutionKeyOriginTag + key
	}
	if raw := strings.TrimSpace(node.ResolvedURL); raw != "" {
		return resolutionKeyRawTag + raw
	}
	return ""
}

// originKey renders a normalized origin as a stable comparison string, so
// records witnessing one resolution compare equal across manifests.
func originKey(origin *DependencyOrigin) string {
	normalized := origin.Normalized()
	if normalized == nil {
		return ""
	}
	return normalized.ArtifactURL + "\x00" + normalized.Repository + "\x00" + normalized.Revision
}

// InsertOccurrence inserts node into g, or reconciles it with the records
// already carrying its identity. It is the single insertion entry point for
// detectors (ADR-0036): a lockfile can name one package more than once, and
// which records fold is a rule with one home, not a per-detector check.
//
//   - No node with the ID exists: node is inserted as given.
//   - An existing record witnesses the same resolution (compared by
//     resolutionKey): the records fold — the survivor takes the union of
//     both records' scopes, everything else on the discarded record is
//     dropped — and the survivor is returned.
//   - The existing records witness contradicting resolutions: node is
//     inserted under an ephemeral discriminator (identitykit.EphemeralID) so
//     both records stay alive for consolidation to finalize. The ephemeral
//     form never reaches a user-visible document — FinalizeGraphIdentity
//     folds or replaces it first, and a graph holding ephemeral records
//     reports so via HasEphemeralOccurrences.
//
// The discriminator is a content-free counter, never derived from the
// evidence that distinguished the records: readable IDs are published, and
// raw resolution strings can carry credentials and machine paths.
func (g *Graph) InsertOccurrence(node *Dependency) (*Dependency, error) {
	if g == nil || node == nil {
		return nil, ErrNilNode
	}
	if node.ID == "" {
		return nil, ErrEmptyNodeID
	}
	existing, ok := g.Node(node.ID)
	if !ok {
		if err := g.AddNode(node); err != nil {
			return nil, fmt.Errorf("insert occurrence %q: %w", node.ID, err)
		}
		return node, nil
	}
	key := resolutionKey(node)
	if resolutionKey(existing) == key {
		for _, scope := range node.Scopes {
			existing.AddScope(scope)
		}
		return existing, nil
	}
	// Contradicting resolutions: a repeated witness of an already-recorded
	// sibling resolution folds into that sibling instead of minting yet
	// another discriminator.
	next := 1
	var match *Dependency
	g.WalkNodes(func(candidate *Dependency) bool {
		if candidate == nil || !identitykit.IsEphemeralID(candidate.ID) || identitykit.EphemeralBase(candidate.ID) != node.ID {
			return true
		}
		// The next ordinal clears the highest live sibling, not the sibling
		// count: removals and non-contiguous discriminators in a decoded
		// graph must not make a fresh occurrence collide with a live one.
		if tail, ok := strings.CutPrefix(candidate.ID[len(node.ID):], "\x00o"); ok {
			if n, err := strconv.Atoi(tail); err == nil && n >= next {
				next = n + 1
			}
		}
		if match == nil && resolutionKey(candidate) == key {
			match = candidate
		}
		return true
	})
	if match != nil {
		for _, scope := range node.Scopes {
			match.AddScope(scope)
		}
		return match, nil
	}
	discriminated := node.Clone()
	discriminated.ID = identitykit.EphemeralID(node.ID, next)
	if err := g.AddNode(discriminated); err != nil {
		return nil, fmt.Errorf("insert contradicting occurrence of %q: %w", node.ID, err)
	}
	return discriminated, nil
}

// HasEphemeralOccurrences reports whether the graph still holds records
// under ephemeral insertion discriminators — records FinalizeGraphIdentity
// has not yet folded or finalized. A graph in this state must not be
// serialized into a user-visible document or persistent store.
func (g *Graph) HasEphemeralOccurrences() bool {
	if g == nil {
		return false
	}
	found := false
	g.WalkNodes(func(node *Dependency) bool {
		if node != nil && identitykit.IsEphemeralID(node.ID) {
			found = true
			return false
		}
		return true
	})
	return found
}
