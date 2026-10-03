#!/usr/bin/env bash
# Builds, vets and unit-tests a bomly-cli checkout against this SDK checkout,
# before anything is tagged. A temporary go.work outside both repositories
# joins them, so neither checkout gains a file and the CLI's go.mod pin is
# untouched. Used by `make cli-test` and the cli-compat CI job.
set -euo pipefail

sdk="$(cd "$(dirname "$0")/.." && pwd)"
cli="${CLI:-$sdk/../bomly-cli}"
if [ ! -f "$cli/go.mod" ]; then
	echo "no bomly-cli checkout at $cli; set CLI=<path>" >&2
	exit 2
fi
cli="$(cd "$cli" && pwd)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
(cd "$work" && go work init "$cli" "$sdk")
export GOWORK="$work/go.work"

cd "$cli"
echo "bomly-cli at $cli against bomly-sdk at $(go list -m -f '{{.Dir}}' github.com/bomly-dev/bomly-sdk)"
go build ./...
go vet ./...
go test ./...
