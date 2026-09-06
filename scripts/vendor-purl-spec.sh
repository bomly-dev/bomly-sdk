#!/usr/bin/env bash
# Refresh the vendored purl specification type definitions.
#
# The per-type structural rules (namespace required/prohibited, required
# qualifiers) have no Go library that owns them, so purlkit carries a table.
# These files are what the differential test diffs that table against; they
# are copied verbatim from upstream so the table can never drift silently.
#
# Usage: scripts/vendor-purl-spec.sh <commit-sha>
set -euo pipefail

sha="${1:-}"
if [ -z "$sha" ]; then
	echo "usage: $0 <commit-sha>" >&2
	echo "resolve one with: git ls-remote https://github.com/package-url/purl-spec main" >&2
	exit 2
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
dest="$root/purlkit/testdata/purl-spec/types"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

curl -fsSL "https://codeload.github.com/package-url/purl-spec/tar.gz/$sha" \
	| tar -xz -C "$work"

src="$work/purl-spec-$sha/types"
if [ ! -d "$src" ]; then
	echo "no types/ directory at $sha" >&2
	exit 1
fi

rm -f "$dest"/*-definition.json
mkdir -p "$dest"
cp "$src"/*-definition.json "$dest/"

echo "vendored $(ls "$dest" | wc -l | tr -d ' ') type definitions from $sha"
echo "update the commit recorded in purlkit/testdata/purl-spec/SOURCE.md"
