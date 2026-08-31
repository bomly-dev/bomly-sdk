package sdk

import "sort"

// Merging is where this model loses data, and it loses it the same few ways
// every time. The ADR-0037 fields alone brought merges for licenses, origins,
// external references, digests, contacts, scopes, edge kinds, and document
// assertions -- and review found the same defects in more than one of them:
// a first-wins rule silently dropping a better value, an early return leaving
// an ungated claim visible, an unsorted result making a document's bytes
// depend on read order, and a merge admitting a value a constructor would
// have refused.
//
// So the rules are named here rather than rewritten per field. A field
// declares which class it belongs to, and the class decides. Fixing a class
// fixes every field in it, which is the difference between this and eight
// correct-looking merge functions.
//
// The classes:
//
//   - FillGap: a scalar where disagreement is not resolvable. The first
//     stated value stands; a later one fills only a gap. Document name,
//     description, homepage.
//   - Union: a set where both sides are true at once. Deduplicated and
//     sorted. Scopes, origins, locations, creators, external references.
//   - Strongest: an ordered vocabulary where one value dominates. Scope
//     (runtime over development), edge kind (a dependency claim over a
//     structural one), reachability (reachable over unreachable).
//
// What is deliberately absent is a LastWins class. Nothing in this model
// should overwrite a stated value with a later one: every field where that
// looked right turned out to be a FillGap whose gap test was missing.

// MergeFillGap returns the current value when it is stated, and the
// replacement only when there is a gap to fill.
//
// The gate matters as much as the rule. The destination is checked for
// publishability before the gap is measured, so an unpublishable non-empty
// value does not count as "stated": leaving it in place would block a valid
// replacement and then be dropped at encode, losing both. That defect was
// found in the M1 review and is the reason this takes a validity test rather
// than comparing against the zero value.
func MergeFillGap[T comparable](current, next T, publishable func(T) bool) T {
	var zero T
	stated := current != zero
	if stated && publishable != nil && !publishable(current) {
		stated = false
	}
	if stated {
		return current
	}
	if publishable != nil && next != zero && !publishable(next) {
		return zero
	}
	return next
}

// MergeUnion appends the members of next that are not already in current,
// keyed by key, and returns the result sorted by that key.
//
// It never returns early. A merge that returns when next is empty leaves the
// destination exactly as it was -- including any member that would not
// survive its own gate -- so an ungated claim stays visible in process and
// disappears only at encode. Running the whole pass unconditionally is what
// makes the gate total.
//
// Sorted because documents are built from these: two runs that found the same
// members in a different order must produce the same bytes.
func MergeUnion[T any](current, next []T, key func(T) string, publishable func(T) (T, bool)) []T {
	seen := make(map[string]struct{}, len(current)+len(next))
	merged := make([]T, 0, len(current)+len(next))
	for _, group := range [2][]T{current, next} {
		for _, item := range group {
			cleaned := item
			if publishable != nil {
				normalized, ok := publishable(item)
				if !ok {
					continue
				}
				cleaned = normalized
			}
			identity := key(cleaned)
			if _, duplicate := seen[identity]; duplicate {
				continue
			}
			seen[identity] = struct{}{}
			merged = append(merged, cleaned)
		}
	}
	if len(merged) == 0 {
		return nil
	}
	sort.SliceStable(merged, func(i, j int) bool { return key(merged[i]) < key(merged[j]) })
	return merged
}

// MergeStrongest returns whichever value ranks higher, treating an unranked
// value as absent so a stated value always beats an unstated one.
//
// rank must be a total order on the vocabulary. Ties keep the current value,
// which makes the result independent of the order the two sides arrived in --
// a property two graphs merged in either direction depend on.
func MergeStrongest[T comparable](current, next T, rank func(T) int) T {
	var zero T
	switch {
	case next == zero:
		return current
	case current == zero:
		return next
	case rank(next) > rank(current):
		return next
	default:
		return current
	}
}
