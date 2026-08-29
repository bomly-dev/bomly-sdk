package identitykit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxInputSize bounds every untrusted identity string before parsing,
// matching purlkit's input bound. A dumb byte cap, frozen once pinned by
// test.
const maxInputSize = 1 << 20

// FallbackPrefix marks the coordinate-fallback base family, keeping it
// structurally distinct from the canonical-PURL family (which always starts
// with "pkg:").
const FallbackPrefix = "coord:"

// fallbackFieldCount is the number of coordinate fields in a fallback base:
// ecosystem, package manager, type, org, name, version.
const fallbackFieldCount = 6

// idDelimiter separates the readable base from its occurrence suffix: a
// single ASCII space, reserved in both base families — a canonical PURL
// percent-encodes spaces by construction, and fallback fields escape them
// here.
const idDelimiter = ' '

// fallbackJoiner separates the escaped coordinate fields of a fallback
// base. Fields escape it, so splitting on it is unambiguous.
const fallbackJoiner = '/'

const upperHex = "0123456789ABCDEF"

func fieldNeedsEscape(c byte) bool {
	return c == byte(idDelimiter) || c == '%' || c == byte(fallbackJoiner) || c < 0x20 || c == 0x7f
}

// EscapeField percent-encodes the bytes that would make a coordinate field
// ambiguous inside a readable ID — the space delimiter, the percent sign
// itself, the '/' field joiner, and control characters (0x00–0x1F and
// 0x7F) — plus every byte that is not part of a valid UTF-8 sequence, each
// rendered as '%' plus two uppercase hex digits. Every other byte passes
// through untouched, so the escaped form stays readable, is always valid
// UTF-8, and survives JSON transport byte for byte (encoders replace
// invalid sequences with U+FFFD, which would silently change a graph key).
func EscapeField(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return r < 0x80 && fieldNeedsEscape(byte(r)) }) && utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && size == 1) || (size == 1 && fieldNeedsEscape(s[i])) {
			c := s[i]
			b.WriteByte('%')
			b.WriteByte(upperHex[c>>4])
			b.WriteByte(upperHex[c&0x0f])
			i++
			continue
		}
		b.WriteString(s[i : i+size])
		i += size
	}
	return b.String()
}

// UnescapeField reverses EscapeField strictly: escape sequences must be
// '%' plus two uppercase hex digits, a raw byte EscapeField would have
// escaped is rejected, and the decoded value must re-escape to exactly the
// input — which also rejects an escape of a byte EscapeField would have
// left raw ("%41" beside "A"). Any laxity would give one field value two
// accepted spellings, letting equivalent identities keep different graph
// keys; there is exactly one escaped spelling per field value.
func UnescapeField(s string) (string, error) {
	if len(s) > maxInputSize {
		return "", fmt.Errorf("identitykit: field exceeds %d bytes", maxInputSize)
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' {
			if i+2 >= len(s) {
				return "", fmt.Errorf("identitykit: truncated escape sequence in field")
			}
			hi := upperHexValue(s[i+1])
			lo := upperHexValue(s[i+2])
			if hi < 0 || lo < 0 {
				return "", fmt.Errorf("identitykit: invalid escape sequence %q in field", s[i:i+3])
			}
			b.WriteByte(byte(hi<<4 | lo))
			i += 2
			continue
		}
		if fieldNeedsEscape(c) {
			return "", fmt.Errorf("identitykit: unescaped byte %#x in field", c)
		}
		b.WriteByte(c)
	}
	decoded := b.String()
	// Canonicality is re-derivation: the decoded value must render back to
	// the input, byte for byte, under the full escape rule — including the
	// UTF-8-validity half that a per-escape check cannot see.
	if EscapeField(decoded) != s {
		return "", fmt.Errorf("identitykit: non-canonical field spelling")
	}
	return decoded, nil
}

func upperHexValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return -1
	}
}

// FallbackIdentity renders the coordinate-fallback readable base for a node
// with no derivable package URL: the "coord:" prefix followed by the six
// escaped coordinate fields — ecosystem, package manager, type, org, name,
// version — joined by '/'. Fields escape the joiner, the space delimiter,
// percent, and control characters, so the rendering is injective and never
// contains an unescaped space. Callers decide when a node is too empty to
// identify; this function always renders.
func FallbackIdentity(ecosystem, packageManager, pkgType, org, name, version string) string {
	fields := [fallbackFieldCount]string{ecosystem, packageManager, pkgType, org, name, version}
	var b strings.Builder
	b.WriteString(FallbackPrefix)
	for i, field := range fields {
		if i > 0 {
			b.WriteByte(byte(fallbackJoiner))
		}
		b.WriteString(EscapeField(field))
	}
	return b.String()
}

// ParseFallbackIdentity decodes a coordinate-fallback base back into its
// six fields, in FallbackIdentity's field order. It reports ok=false for
// oversized input, a missing "coord:" prefix, a wrong field count, or a
// field that fails strict unescaping.
func ParseFallbackIdentity(id string) (fields [6]string, ok bool) {
	if len(id) > maxInputSize || !strings.HasPrefix(id, FallbackPrefix) {
		return fields, false
	}
	parts := strings.Split(id[len(FallbackPrefix):], string(fallbackJoiner))
	if len(parts) != fallbackFieldCount {
		return [6]string{}, false
	}
	for i, part := range parts {
		value, err := UnescapeField(part)
		if err != nil {
			return [6]string{}, false
		}
		fields[i] = value
	}
	return fields, true
}

// OccurrenceSuffix derives the readable suffix for an admitted occurrence
// facet: the first six bytes of its SHA-256, rendered as twelve lowercase
// hex characters. The empty facet is the default occurrence and has no
// suffix.
func OccurrenceSuffix(facet string) string {
	if facet == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(facet))
	return hex.EncodeToString(digest[:6])
}

// OrdinalSuffix renders the run-local ordinal suffix — "o" followed by a
// decimal without leading zeros — for records distinguishable only by raw
// evidence. Ordinals start at 1; values below 1 render as the empty suffix
// rather than a corrupt one.
func OrdinalSuffix(n int) string {
	if n < 1 {
		return ""
	}
	return "o" + strconv.Itoa(n)
}

// JoinID appends an occurrence suffix to a readable base with the single
// ASCII space delimiter. An empty suffix returns the base unchanged, and an
// empty base returns the empty string — a suffix alone is not an ID.
func JoinID(base, suffix string) string {
	if base == "" || suffix == "" {
		return base
	}
	return base + string(idDelimiter) + suffix
}

// SplitID splits a readable ID into its base and occurrence suffix at the
// last space when the trailing token matches the suffix grammar and the
// base is non-empty — a suffix alone is not an ID; otherwise the whole
// value is the base with no suffix. Both base families escape the delimiter
// inside fields, so the split is unambiguous by structure for every ID this
// module mints. Oversized input is returned whole.
func SplitID(id string) (base, suffix string) {
	if len(id) > maxInputSize {
		return id, ""
	}
	idx := strings.LastIndexByte(id, byte(idDelimiter))
	if idx < 1 {
		return id, ""
	}
	candidate := id[idx+1:]
	if !IsOccurrenceSuffix(candidate) {
		return id, ""
	}
	return id[:idx], candidate
}

// IsOccurrenceSuffix reports whether a token matches one of the two suffix
// grammars: exactly twelve lowercase hex characters (the facet-hash form),
// or "o" followed by a decimal with no leading zero (the run-local ordinal
// form). The grammars are disjoint — 'o' is not a hex digit.
func IsOccurrenceSuffix(s string) bool {
	if len(s) == 12 && isLowerHex(s) {
		return true
	}
	return isOrdinal(s)
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func isOrdinal(s string) bool {
	if len(s) < 2 || s[0] != 'o' || s[1] < '1' || s[1] > '9' {
		return false
	}
	for i := 2; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
