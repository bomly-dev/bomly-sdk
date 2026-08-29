package identitykit

import (
	"strconv"
	"strings"
)

// ephemeralMarker separates an ephemeral discriminator from its base. NUL
// can never appear in a readable ID — both base families escape control
// characters — so the ephemeral and readable ID families are structurally
// disjoint.
const ephemeralMarker = "\x00"

// EphemeralID mints the insertion-time discriminator that keeps
// contradicting same-base records alive in one graph before consolidation
// finalizes them: the base, a NUL byte, and "o" plus a decimal ordinal
// starting at 1. The form is explicitly non-durable: it may cross
// in-process and intra-run plugin-wire boundaries, but it never reaches a
// user-visible document or a persistent store — finalization replaces it
// first. An empty base or an ordinal below 1 returns the empty string,
// which graph insertion rejects loudly rather than colliding silently.
func EphemeralID(base string, n int) string {
	if base == "" || n < 1 {
		return ""
	}
	return base + ephemeralMarker + "o" + strconv.Itoa(n)
}

// IsEphemeralID reports whether an ID carries an ephemeral discriminator.
func IsEphemeralID(id string) bool {
	return strings.Contains(id, ephemeralMarker)
}

// EphemeralBase returns the readable base of an ephemeral ID — everything
// before the first NUL — or the value unchanged when it carries no
// discriminator.
func EphemeralBase(id string) string {
	if i := strings.Index(id, ephemeralMarker); i >= 0 {
		return id[:i]
	}
	return id
}
