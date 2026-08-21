package sdk

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

// maxOriginRevisionLength bounds a recorded revision. Commit hashes and tags
// are far shorter; anything longer is not a revision.
const maxOriginRevisionLength = 128

// DependencyOrigin is where a dependency was resolved from, as asserted by the
// manifest the detector read. It is distilled at detection time from the
// manifest's structured source fields -- not derivable later from the raw
// ResolvedURL, which merges several fields and loses their meaning. The name
// follows the two standards that record this concept as a structured value:
// Go modules' Origin (URL, ref, hash) and PEP 610's "Direct URL Origin".
//
// A dependency has one origin: either it was downloaded as an artifact or it
// was resolved from a repository, never both. An empty origin means the
// manifest had nothing publishable to say, which is the normal case for a
// dependency whose lockfile records only a registry or index root. Consumers
// such as SBOM export should publish nothing rather than guess.
//
// This is detection data. Registry-side enrichment that resolves a source
// repository from package identity is a different, weaker claim and lives on
// its own fields (for example PackageScorecard.Repository), never here.
type DependencyOrigin struct {
	// ArtifactURL is the exact file the package was downloaded from.
	ArtifactURL string `json:"artifact_url,omitempty"`
	// Repository is the source repository the package was resolved from.
	Repository string `json:"repository,omitempty"`
	// Revision is the revision pinned in Repository, when the lockfile
	// recorded one. Never set without Repository.
	Revision string `json:"revision,omitempty"`
}

// ArtifactOrigin records the exact artifact a package was resolved from.
// Callers pass the lockfile field verbatim. It returns nil when the value is
// not a publishable location, since a missing origin is correct output and a
// wrong one is not.
func ArtifactOrigin(rawURL string) *DependencyOrigin {
	normalized, ok := NormalizeOriginURL(rawURL, false)
	if !ok {
		return nil
	}
	return &DependencyOrigin{ArtifactURL: normalized}
}

// RepositoryOrigin records the source repository a package was resolved from,
// plus the revision that was pinned. It returns nil when the URL is not a
// publishable location; an unusable revision drops only the revision, keeping
// the repository.
func RepositoryOrigin(rawURL, revision string) *DependencyOrigin {
	normalized, ok := NormalizeOriginURL(rawURL, true)
	if !ok {
		return nil
	}
	origin := &DependencyOrigin{Repository: normalized}
	if pinned := strings.TrimSpace(revision); isValidOriginRevision(pinned) {
		origin.Revision = pinned
	}
	return origin
}

// NormalizeOriginURL is the single rule every published origin URL satisfies.
// Apply it when recording a URL and again when reading one back, so an origin
// that arrives from a plugin or a hand-built graph is held to the same standard
// as one from a built-in component.
//
// A value passes only when it is an absolute http or https URL with a host, a
// non-empty path, and no embedded credentials; the result is re-serialized from
// the parse rather than returned as given. Everything else -- local paths,
// file://, git@host:org/repo, ssh://, git+ssh://, "git+" prefixes, registry and
// index roots, and URLs carrying userinfo -- is rejected, so filesystem layout
// and credentials cannot reach a published document.
//
// The repository argument selects the repository form: query and fragment are
// dropped, because they carry the ref that was requested rather than the one
// that was resolved, which callers pass separately. The artifact form drops the
// fragment (a checksum or anchor, never part of the location) and rejects a
// value carrying a query, which marks a signed or tokenized link rather than a
// stable location.
func NormalizeOriginURL(raw string, repository bool) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", false
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return "", false
	}
	// Hostname also rejects a malformed host such as "https://:8080/pkg".
	if parsed.Hostname() == "" || parsed.User != nil {
		return "", false
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	// Hosts are case-insensitive, so two records writing one host differently
	// name the same location. Without this they would compare unequal and
	// reconcile to a disagreement, losing an origin to formatting alone. The
	// path is left alone: it is case-sensitive.
	parsed.Host = strings.ToLower(parsed.Host)
	// An explicit default port names the same origin as no port at all, so
	// dropping it keeps two spellings of one location from reading as a
	// disagreement.
	if port := parsed.Port(); port != "" {
		// url.Parse only checks that a port is numeric, so a value no client
		// could connect to still reaches here.
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return "", false
		}
		// Rewrite the port from its number, so one port written two ways --
		// Port() preserves leading zeros -- gives one location. A port that
		// is the scheme's default is dropped, since naming it says nothing.
		// Rebuild from the bare hostname, restoring brackets when the host
		// was written as an IP literal. Keying off the original spelling
		// rather than off the hostname's contents keeps this correct however
		// url.Parse's host validation changes: an unbracketed literal would
		// name a different host.
		host := parsed.Hostname()
		if strings.HasPrefix(parsed.Host, "[") {
			host = "[" + host + "]"
		}
		if (parsed.Scheme == "https" && number == 443) || (parsed.Scheme == "http" && number == 80) {
			parsed.Host = host
		} else {
			parsed.Host = host + ":" + strconv.Itoa(number)
		}
	}
	parsed.Fragment = ""
	parsed.RawFragment = ""
	// A host root names a server, not a package: a registry or index root on
	// the artifact side, and no repository at all on the other. An empty path
	// would also make a "<url>@<revision>" locator re-parse as userinfo.
	if strings.Trim(parsed.Path, "/") == "" {
		return "", false
	}
	if repository {
		parsed.RawQuery = ""
		parsed.ForceQuery = false
	} else if parsed.RawQuery != "" || parsed.ForceQuery {
		return "", false
	}
	// Canonicalize the escaped form, not parsed.Path: Path is already decoded,
	// where "%2F" and "/" are indistinguishable, and re-encoding from it would
	// turn an escaped slash into a path separator and change the location.
	escaped := canonicalEscapes(parsed.EscapedPath())
	decodedPath, err := url.PathUnescape(escaped)
	if err != nil {
		return "", false
	}
	parsed.Path = decodedPath
	parsed.RawPath = escaped
	normalized := parsed.String()
	if normalized == "" {
		return "", false
	}
	return normalized, true
}

// canonicalEscapes rewrites a path so two spellings of one location compare
// equal. RFC 3986 says a percent-escaped unreserved character means the same as
// the character itself, so "%7Euser" and "~user" name one path; without this
// they would reconcile to a disagreement and lose a valid origin to formatting
// alone. Reserved characters keep their escapes, since there the escape changes
// what the path means, but their hex is written one way.
func canonicalEscapes(path string) string {
	if !strings.Contains(path, "%") {
		return path
	}
	var out strings.Builder
	out.Grow(len(path))
	for i := 0; i < len(path); i++ {
		if path[i] != '%' || i+2 >= len(path) {
			out.WriteByte(path[i])
			continue
		}
		decoded, ok := unhex(path[i+1], path[i+2])
		if !ok {
			out.WriteByte(path[i])
			continue
		}
		if isUnreservedByte(decoded) {
			out.WriteByte(decoded)
		} else {
			out.WriteString("%")
			out.WriteString(strings.ToUpper(path[i+1 : i+3]))
		}
		i += 2
	}
	return out.String()
}

// unhex decodes one percent-escape pair.
func unhex(high, low byte) (byte, bool) {
	value := 0
	for _, digit := range []byte{high, low} {
		value <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			value |= int(digit - '0')
		case digit >= 'a' && digit <= 'f':
			value |= int(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			value |= int(digit-'A') + 10
		default:
			return 0, false
		}
	}
	return byte(value), true
}

// isUnreservedByte reports whether b is unreserved in RFC 3986, meaning its
// escaped and unescaped spellings are equivalent.
func isUnreservedByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '-', b == '.', b == '_', b == '~':
		return true
	default:
		return false
	}
}

// Empty reports whether o names no publishable location -- including an origin
// whose values do not survive validation, so a caller that checks Empty can
// read Normalized without a second nil check.
func (o *DependencyOrigin) Empty() bool {
	return o.Normalized() == nil
}

// Normalized returns o with every value re-validated, or nil when nothing
// publishable survives. Read origin through this rather than reading the fields
// directly: it is what keeps a plugin-supplied or hand-built value from
// reaching a published document unchecked. An artifact wins over a repository
// in the case -- which the constructors never produce -- where both are set.
func (o *DependencyOrigin) Normalized() *DependencyOrigin {
	if o == nil {
		return nil
	}
	if artifact, ok := NormalizeOriginURL(o.ArtifactURL, false); ok {
		return &DependencyOrigin{ArtifactURL: artifact}
	}
	repository, ok := NormalizeOriginURL(o.Repository, true)
	if !ok {
		return nil
	}
	normalized := &DependencyOrigin{Repository: repository}
	if pinned := strings.TrimSpace(o.Revision); isValidOriginRevision(pinned) {
		normalized.Revision = pinned
	}
	return normalized
}

// originWire carries DependencyOrigin's fields without its methods, so the JSON
// hooks below can encode and decode without recursing.
type originWire DependencyOrigin

// UnmarshalJSON applies the origin rule as a value arrives, so a location that
// would be rejected on read cannot be stored, forwarded to another component,
// or written back out. A record of a disagreement survives decoding: it is not
// a location, but it is a fact worth keeping.
func (o *DependencyOrigin) UnmarshalJSON(data []byte) error {
	var wire originWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	decoded := DependencyOrigin(wire)
	normalized := decoded.Normalized()
	if normalized == nil {
		*o = DependencyOrigin{}
		return nil
	}
	*o = *normalized
	return nil
}

// MarshalJSON applies the same rule on the way out, so a hand-built value that
// never passed through the constructors cannot leave this process either.
func (o DependencyOrigin) MarshalJSON() ([]byte, error) {
	if normalized := o.Normalized(); normalized != nil {
		return json.Marshal(originWire(*normalized))
	}
	return json.Marshal(originWire{})
}

// Clone returns a deep copy.
func (o *DependencyOrigin) Clone() *DependencyOrigin {
	if o == nil {
		return nil
	}
	clone := *o
	return &clone
}

// isValidOriginRevision reports whether revision is safe to publish beside a
// repository. The charset keeps commit hashes, tags, and branch-style refs
// while excluding whitespace, "@", and percent escapes, which would break
// locator grammars such as SPDX's "git+<url>@<revision>".
func isValidOriginRevision(revision string) bool {
	if revision == "" || len(revision) > maxOriginRevisionLength {
		return false
	}
	for _, r := range revision {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-', r == '+', r == '/':
		default:
			return false
		}
	}
	return true
}
