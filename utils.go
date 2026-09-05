package sdk

func includesName(include []string, name string) bool {
	if len(include) == 0 {
		return true
	}
	for _, candidate := range include {
		if candidate == name {
			return true
		}
	}
	return false
}

func excludesName(exclude []string, name string) bool {
	for _, candidate := range exclude {
		if candidate == name {
			return true
		}
	}
	return false
}

// maxMergeCapacity bounds the preallocation hint a merge may ask for. It is a
// dumb count, not a limit on the merge: a hint is only a hint, and append and
// the map both grow past it, so a genuinely larger set still merges in full.
const maxMergeCapacity = 1 << 20

// mergeCapacity sizes the preallocation for a merge of two collections whose
// lengths came from decoded, untrusted input. Each side is clamped before the
// addition rather than the sum after it, so the sum cannot wrap: an overflowed
// hint reaches make as a negative size, which panics.
func mergeCapacity(a, b int) int {
	return min(a, maxMergeCapacity) + min(b, maxMergeCapacity)
}
