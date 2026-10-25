package plugin

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/bomly-dev/bomly-sdk/model"
)

// Access is a managed plugin's own disclosure of the host access it expects:
// which filesystem areas it reads and writes, which network destinations it
// contacts, which environment variables it reads, and which commands it
// starts. It is the "access" block of a package manifest (bomly-plugin.json,
// PackageManifestSchemaVersion), written by the plugin's publisher, and a
// host shows it to the user before the user enables the plugin.
//
// It is disclosure, not enforcement. A managed plugin is a native process
// with the invoking user's authority; nothing in Bomly restricts it to what
// it declared, and a declaration is not evidence that the plugin behaves as
// declared. A host must present it as the publisher's unverified claim.
//
// A manifest without an access block discloses nothing, which a host must
// treat as unknown and unrestricted -- never as "needs no access". A present
// block with every list empty is a claim that the plugin needs none.
//
// Every list is bounded, deduplicated and sorted; network destinations are
// canonicalized. The vocabularies are open, as Requirement's is: a
// well-formed entry this SDK does not recognize is kept, so an older host
// shows a newer plugin's claim rather than hiding it, and a malformed entry
// fails Validate rather than being dropped, because silently dropping an
// entry would under-report access.
type Access struct {
	// FilesystemRead lists the areas the plugin reads; see FilesystemScope.
	FilesystemRead []FilesystemScope `json:"filesystemRead,omitempty"`
	// FilesystemWrite lists the areas the plugin writes or deletes in.
	// Writing an area implies reading it.
	FilesystemWrite []FilesystemScope `json:"filesystemWrite,omitempty"`
	// Network lists the destinations the plugin contacts: a host name
	// ("api.osv.dev"), a host and all its subdomains ("*.github.com"), or
	// "*" for destinations it cannot name in advance, such as a
	// user-configured registry. Destinations are descriptive patterns, not
	// a firewall rule.
	Network []string `json:"network,omitempty"`
	// Environment lists the environment variables the plugin reads, by name
	// ("GITHUB_TOKEN"), by prefix ("BOMLY_HTTP_*"), or "*" for all of them.
	// Names only: a host never displays or logs a value.
	Environment []string `json:"environment,omitempty"`
	// Subprocesses lists the commands the plugin starts, by base name
	// ("go", "npm"), or "*" for commands it cannot name in advance.
	Subprocesses []string `json:"subprocesses,omitempty"`
}

// FilesystemScope names an area of the filesystem a plugin touches, as a
// class rather than a path, because paths differ by machine and operating
// system while the question a user is answering -- does this read my
// project, write my home directory -- does not.
type FilesystemScope string

const (
	// FilesystemProject is the scan target: the project or checkout being
	// scanned.
	FilesystemProject FilesystemScope = "project"
	// FilesystemTemp is the operating system's temporary directory.
	FilesystemTemp FilesystemScope = "temp"
	// FilesystemCache is the user's cache directory (os.UserCacheDir), such
	// as a build or download cache a tool keeps there.
	FilesystemCache FilesystemScope = "cache"
	// FilesystemHome is the user's home directory beyond the cache.
	FilesystemHome FilesystemScope = "home"
	// FilesystemAny is anywhere the user can reach.
	FilesystemAny FilesystemScope = "any"
)

// knownFilesystemScopes is this SDK's scope vocabulary.
var knownFilesystemScopes = []FilesystemScope{FilesystemAny, FilesystemCache, FilesystemHome, FilesystemProject, FilesystemTemp}

// Known reports whether s is in this SDK's scope vocabulary.
func (s FilesystemScope) Known() bool {
	return slices.Contains(knownFilesystemScopes, s)
}

// AccessAny is the entry that stands for every destination, variable or
// command in its list.
const AccessAny = "*"

// MaxAccessEntries bounds each Access list, and MaxAccessEntryLength each
// entry: resource bounds on publisher-supplied manifest input. The entry
// bound is the DNS name limit, the longest entry any list needs.
const (
	MaxAccessEntries     = 32
	MaxAccessEntryLength = 253
)

var (
	// filesystemScopeGrammar is the scope-token shape.
	filesystemScopeGrammar = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	// environmentNameGrammar is the POSIX portable environment-variable
	// name (POSIX.1-2017, XBD 8.1: letters, digits and underscore from the
	// portable character set, not beginning with a digit), optionally
	// ending in "*" to name a prefix. No library in this module's pinned
	// dependencies owns that grammar, and it is one line, so it is written
	// here rather than imported; FuzzAccess covers it.
	environmentNameGrammar = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\*?$`)
)

// Normalized returns the disclosure with every list deduplicated and sorted
// and every network destination canonicalized through
// model.CanonicalHostname. An entry that cannot be canonicalized is kept as
// written, so Validate reports it instead of the normalization hiding it.
func (a Access) Normalized() Access {
	return Access{
		FilesystemRead:  normalizedSet(a.FilesystemRead, func(s FilesystemScope) FilesystemScope { return s }),
		FilesystemWrite: normalizedSet(a.FilesystemWrite, func(s FilesystemScope) FilesystemScope { return s }),
		Network:         normalizedSet(a.Network, canonicalDestination),
		Environment:     normalizedSet(a.Environment, func(s string) string { return s }),
		Subprocesses:    normalizedSet(a.Subprocesses, func(s string) string { return s }),
	}
}

func normalizedSet[T ~string](values []T, canonical func(T) T) []T {
	if len(values) == 0 {
		return nil
	}
	out := make([]T, len(values))
	for i, value := range values {
		out[i] = canonical(value)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// canonicalDestination canonicalizes a host or "*.host" destination; "*"
// and an entry the host gate refuses come back as given.
func canonicalDestination(destination string) string {
	if destination == AccessAny {
		return destination
	}
	host, wildcard := strings.CutPrefix(destination, "*.")
	canonical, ok := model.CanonicalHostname(host)
	if !ok {
		return destination
	}
	if wildcard {
		return "*." + canonical
	}
	return canonical
}

// Validate checks every list against its bound and grammar: filesystem
// scopes are lower-case tokens; network destinations are "*", a host name,
// or "*." and a host name, each accepted by model.CanonicalHostname;
// environment entries are "*" or a POSIX name, optionally ending in "*";
// subprocess entries are "*" or a command base name -- no path separator,
// whitespace or control character. Unknown but well-formed scopes pass.
func (a Access) Validate() error {
	checks := []struct {
		field  string
		values []string
		valid  func(string) bool
	}{
		{"filesystemRead", scopeStrings(a.FilesystemRead), filesystemScopeGrammar.MatchString},
		{"filesystemWrite", scopeStrings(a.FilesystemWrite), filesystemScopeGrammar.MatchString},
		{"network", a.Network, validDestination},
		{"environment", a.Environment, func(s string) bool { return s == AccessAny || environmentNameGrammar.MatchString(s) }},
		{"subprocesses", a.Subprocesses, validCommand},
	}
	for _, check := range checks {
		if len(check.values) > MaxAccessEntries {
			return fmt.Errorf("access %s lists %d entries, more than %d", check.field, len(check.values), MaxAccessEntries)
		}
		for _, value := range check.values {
			if len(value) > MaxAccessEntryLength {
				return fmt.Errorf("access %s entry exceeds %d bytes", check.field, MaxAccessEntryLength)
			}
			if !check.valid(value) {
				return fmt.Errorf("access %s entry %q is malformed", check.field, value)
			}
		}
	}
	return nil
}

func scopeStrings(scopes []FilesystemScope) []string {
	out := make([]string, len(scopes))
	for i, scope := range scopes {
		out[i] = string(scope)
	}
	return out
}

func validDestination(destination string) bool {
	if destination == AccessAny {
		return true
	}
	host, _ := strings.CutPrefix(destination, "*.")
	_, ok := model.CanonicalHostname(host)
	return ok
}

func validCommand(command string) bool {
	if command == AccessAny {
		return true
	}
	if command == "" || command == "." || command == ".." || !utf8.ValidString(command) || model.ContainsControlChar(command) {
		return false
	}
	return !strings.ContainsAny(command, "/\\ \t")
}

// accessWire carries Access's fields without its methods, so the codec
// below can encode and decode without recursing.
type accessWire Access

// UnmarshalJSON normalizes the disclosure as it is read.
func (a *Access) UnmarshalJSON(data []byte) error {
	var wire accessWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	*a = Access(wire).Normalized()
	return nil
}

// MarshalJSON normalizes the disclosure as it is written. A present block
// with no entries encodes as {}, a claim of no access, distinct from an
// absent block.
func (a Access) MarshalJSON() ([]byte, error) {
	return json.Marshal(accessWire(a.Normalized()))
}

// ValidateAccess validates an optional disclosure: nil -- the legacy
// "unknown" -- is valid, and a present one must pass Access.Validate.
func ValidateAccess(access *Access) error {
	if access == nil {
		return nil
	}
	return access.Validate()
}
