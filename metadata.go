package sdk

import (
	"sort"
	"strings"
)

// Metadata maps are the model's escape hatch: a place for an ecosystem or a
// plugin to carry something the typed fields do not hold. They are also where
// typed fields go to be reinvented, so the policy is written down rather than
// assumed.
//
// # The reserved prefix
//
// Keys beginning with "bomly." are reserved for this project. A plugin that
// writes one is writing into Bomly's own namespace, where a future release may
// give the key a meaning -- and the collision surfaces as data quietly read as
// something it is not, which is the worst way to find out. Plugins should
// namespace their keys by their own name.
//
// # What does not belong here
//
// Anything a typed field holds. A stash is invisible to the gates: it is not
// normalized, not validated, not merged by any declared rule, and not
// projected to either document format. A value that lives only in a metadata
// map is a value that will be dropped by an exporter that never learned to
// look for it -- which is exactly what happened to detection licenses, and is
// why MetadataKeyDetectionLicenses is deprecated below.

// ReservedMetadataPrefix is the key prefix reserved for Bomly's own use.
// Component authors namespace their keys by their own component name instead.
const ReservedMetadataPrefix = "bomly."

// IsReservedMetadataKey reports whether a key is in Bomly's reserved
// namespace. The comparison is case-insensitive, since a key differing only in
// case is a collision a reader would not see.
func IsReservedMetadataKey(key string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(key)), ReservedMetadataPrefix)
}

// ReservedMetadataKeys returns the reserved keys present in a metadata map,
// sorted. A component runtime uses it to warn an external plugin that is
// writing into Bomly's namespace, rather than letting the collision be found
// later as data read as the wrong thing.
func ReservedMetadataKeys(metadata map[string]any) []string {
	var found []string
	for key := range metadata {
		if IsReservedMetadataKey(key) {
			found = append(found, key)
		}
	}
	sort.Strings(found)
	return found
}

// mergeMetadataPreservingReserved merges caller metadata onto metadata a
// constructor produced, keeping the constructor's value for any reserved key.
//
// The caller's entries are the ones a producer meant to attach, so they win in
// general. Reserved keys are the exception: that namespace belongs to this
// project, a constructor is what writes into it, and letting a caller's map
// replace a provenance breadcrumb would leave a node claiming a normalization
// history it does not have.
func mergeMetadataPreservingReserved(constructed, caller map[string]any) map[string]any {
	if len(constructed) == 0 && len(caller) == 0 {
		return nil
	}
	merged := make(map[string]any, mergeCapacity(len(constructed), len(caller)))
	for key, value := range caller {
		if IsReservedMetadataKey(key) {
			continue
		}
		merged[key] = value
	}
	for key, value := range constructed {
		merged[key] = value
	}
	return merged
}
