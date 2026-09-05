#!/usr/bin/env bash
# Runs every native Go fuzz target in the module for FUZZTIME each.
#
# Targets are discovered, not listed: AGENTS.md requires every parser of
# untrusted input to ship a fuzz target from its first commit, and a
# hand-maintained list is exactly the place such a target gets forgotten.
# `go test -list` prints test names only, so it is cheap to run per package.
set -euo pipefail

FUZZTIME="${FUZZTIME:-60s}"

cd "$(dirname "${BASH_SOURCE[0]}")/.."

for package in $(go list ./...); do
  targets="$(go test "${package}" -run='^$' -list='^Fuzz' | grep '^Fuzz' || true)"
  for fuzz in ${targets}; do
    echo "==> go test ${package} -run=^\$ -fuzz=^${fuzz}\$ -fuzztime=${FUZZTIME}"
    go test "${package}" -run='^$' -fuzz="^${fuzz}\$" -fuzztime="${FUZZTIME}"
  done
done
