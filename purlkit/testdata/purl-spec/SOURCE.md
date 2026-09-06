# Vendored purl specification type definitions

`types/` holds the `*-definition.json` documents from the package-url
specification repository, copied verbatim. Nothing here is edited: these
files are the authority the differential test in
`../../typeprofile_spec_test.go` diffs `typeProfiles` against, so any change
to them must come from upstream, never from a local fix.

- Source: <https://github.com/package-url/purl-spec>, `types/*-definition.json`
- Commit: `09737022ca6f7306f6be06fa235971087d61e577` (2026-08-25)
- Vendored: 2026-09-06

## Refreshing

```sh
./scripts/vendor-purl-spec.sh <commit-sha>
```

Then run `go test ./purlkit/...`. A failure names the row that drifted: the
specification either grew a rule the table does not carry, or dropped one it
still enforces. Update `typeProfiles` — or, when the divergence is
deliberate, `specDeviations` — and record the new commit above.
