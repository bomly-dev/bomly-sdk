// Package filecache provides shared on-disk caching helpers for matcher, analyzer, and detector implementations.
package filecache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-sdk/system"
)

// Key uniquely identifies one cached auditor result.
type Key struct {
	raw string
}

// NewKey creates a stable cache key from the given fields.
// Callers should pass the most specific identity available.
func NewKey(purl, name, ecosystem, version string) Key {
	raw := fmt.Sprintf("%s|%s|%s|%s", purl, name, ecosystem, version)
	sum := sha256.Sum256([]byte(raw))
	return Key{raw: hex.EncodeToString(sum[:])}
}

// DefaultDir returns the directory a component's cache lives in by default,
// ~/.bomly/cache/<parts...>, for example DefaultDir("licenses", "depsdev").
// It is the one place that location is built, so every component caches under
// the same root and the access a plugin declares ("home") stays true.
//
// When the user's home directory cannot be determined, DefaultDir returns an
// error rather than a relative path. A relative fallback lands in whatever
// directory Bomly happens to run in, which no access declaration describes
// (bomly-planning#115); a component that gets the error runs without a cache
// by passing a nil *FileCache. Each element must be a single, non-empty path
// name.
func DefaultDir(parts ...string) (string, error) {
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, `/\`) {
			return "", fmt.Errorf("cache directory name %q must be a single path element", part)
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate the default cache directory: %w", err)
	}
	if home == "" || !filepath.IsAbs(home) {
		return "", fmt.Errorf("locate the default cache directory: home directory %q is not absolute", home)
	}
	return filepath.Join(append([]string{home, ".bomly", "cache"}, parts...)...), nil
}

// FileCache stores JSON-encoded values on disk with a TTL. A nil *FileCache
// is a valid cache that stores nothing: Get always misses and Set does
// nothing, so a component whose cache directory is unavailable runs uncached
// without guarding every call.
type FileCache struct {
	dir string
	ttl time.Duration
}

type entry[T any] struct {
	CachedAt time.Time `json:"cached_at"`
	Value    T         `json:"value"`
}

// NewFileCache creates a cache rooted at dir with the specified TTL.
func NewFileCache(dir string, ttl time.Duration) (*FileCache, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	return &FileCache{dir: dir, ttl: ttl}, nil
}

func (c *FileCache) path(key Key) string {
	return filepath.Join(c.dir, key.raw+".json")
}

// Get returns the cached value for key if it exists and has not expired. A
// nil cache always misses.
func Get[T any](c *FileCache, key Key) (T, bool) {
	var zero T
	if c == nil {
		return zero, false
	}
	data, err := system.ReadCacheFile(c.path(key))
	if err != nil {
		return zero, false
	}
	var cached entry[T]
	if err := json.Unmarshal(data, &cached); err != nil {
		return zero, false
	}
	if time.Since(cached.CachedAt) > c.ttl {
		return zero, false
	}
	return cached.Value, true
}

// Set writes value to the cache under key. On a nil cache it does nothing.
func Set[T any](c *FileCache, key Key, value T) error {
	if c == nil {
		return nil
	}
	cached := entry[T]{CachedAt: time.Now(), Value: value}
	data, err := json.Marshal(cached)
	if err != nil {
		return fmt.Errorf("marshal cache entry: %w", err)
	}
	return os.WriteFile(c.path(key), data, 0o600)
}
