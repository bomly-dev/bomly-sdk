# Bomly dependency identity — normative specification (v1)

This document fixes every byte of the readable node ID and the v1 content
address defined by ADR-0036 (in bomly-cli's `dev-docs/adr/`). The golden
vectors in [`testdata/identity_vectors.json`](testdata/identity_vectors.json)
are the machine-readable form of this spec; an implementation that disagrees
with a vector is wrong. The words MUST / MUST NOT are used normatively.

## 1. Identity facets

A node's identity is the ordered pair:

1. **Package identity** — the canonical package URL of the node when one is
   derivable, in its *identity form*: qualifiers are filtered through the
   identity-qualifier allowlist (currently empty — every qualifier is
   dropped; URL-valued qualifiers will additionally pass credential and
   local-path gates when the first key is admitted, reserved behavior),
   and the subpath is preserved. When no package URL is derivable, package
   identity is the coordinate-fallback rendering of section 3, taken only
   after identity normalization has run.
2. **Occurrence facet** — empty by default. Assigned at consolidation, and
   only to records established as contradicting, as one of:
   - the first-party sentinel, exactly the bytes `first-party`;
   - `artifact` NUL `<url>`, where `<url>` is the asserted artifact URL
     with query and fragment stripped **before** origin normalization —
     stricter than the publication rule, because a signed or tokenized
     query is a rotating credential;
   - `repository` NUL `<url>` NUL `<revision>`, where `<url>` is the
     normalized repository URL and `<revision>` is the validated revision
     (an empty revision is an empty trailing field).

   NUL joining is injective here because normalized URLs and the revision
   character set are control-free. The raw resolved URL MUST NOT enter any
   facet: it can carry local paths and credentials, varies across machines,
   and hashing does not protect a low-entropy secret from offline guessing.

## 2. Readable ID grammar

```
readable-id   = base [ SP suffix ]
base          = purl-base / fallback-base
purl-base     = "pkg:" ...          ; a canonical package URL (identity form)
fallback-base = "coord:" field "/" field "/" field "/" field "/" field "/" field
suffix        = hash-suffix / ordinal-suffix
hash-suffix   = 12 lowercase-hex
ordinal-suffix= "o" nonzero-digit *digit
```

- The delimiter between base and suffix is a **single ASCII space (0x20)**.
  A canonical package URL percent-encodes spaces by construction, and
  fallback fields escape them (section 3), so a raw space appears only as
  the delimiter.
- Decoding splits on the **last** space whose trailing token matches the
  suffix grammar and whose base half is non-empty — a suffix alone is not
  an ID; a value with no such split is entirely a base. The two
  suffix grammars are disjoint (`o` is not a hex digit), and a hash suffix
  is always exactly twelve characters.
- The two base families are structurally distinct by prefix: `pkg:` versus
  `coord:`.

### Suffix derivation

- **Hash suffix** — the first six bytes of the SHA-256 of the admitted
  occurrence facet, rendered as twelve lowercase hex characters. Used when
  the record's facet is unique within its contested base.
- **Ordinal suffix** — `o` followed by a decimal starting at 1, with no
  leading zeros. Used for records distinguishable only by raw evidence,
  and for records whose admitted facets coincide after identity
  normalization. Ordinals are run-local: within one base they are assigned
  in a stated order — the contradicting records sorted lexicographically
  by the resolution key that established the contradiction, ties broken by
  manifest path, then by first location — never arrival or map-iteration
  order. An ordinal MUST NOT be persisted as a cross-run key.
- The suffix never embeds a raw qualifier, a raw URL, or a hash of raw
  evidence: readable IDs are published in scan JSON and SBOMs.

### Rendering rules

- In a contested base, the project's own first-party record keeps the
  canonical **unsuffixed** base as its ID; its content address still folds
  the first-party sentinel facet.
- A record with no resolution evidence in a contested base keeps the
  unsuffixed base with an empty facet (the "resolution unknown"
  occurrence).

## 3. Fallback base encoding

The fallback base renders the six coordinate fields — ecosystem, package
manager, type, org, name, version, in that order — each escaped, joined by
`/`, prefixed by `coord:`. Field escaping percent-encodes exactly:

- the space delimiter (0x20),
- the percent sign itself (0x25),
- the field joiner `/` (0x2F), and
- control characters (0x00–0x1F and 0x7F),

each as `%` plus two **uppercase** hex digits. All other bytes pass through
untouched. Decoding is strict: escape sequences MUST be `%` + two uppercase
hex digits, and a raw byte from the escape set MUST be rejected — there is
exactly one escaped spelling per field value. (The escape set extends
ADR-0036's enumerated set with the joiner, which is required for injective
six-field parsing; this spec is the normative byte-level authority under
the ADR's "the spec fixes every byte" clause.)

## 4. Content address (v1)

The v1 content address of a node is:

```
address = lowercase-hex( SHA-256( encoding )[0:16] )
encoding = lp("bomly:node:v1") lp(package-identity) lp(occurrence-facet)
lp(s)    = uint32-big-endian(len(s)) s          ; s as UTF-8 bytes
```

- An absent facet is a zero-length field, still length-prefixed.
- The digest is truncated to its **first 16 bytes** (128 bits) and rendered
  as 32 lowercase hex characters.
- The full form is canonical everywhere: a store may re-derive it from the
  facets but MUST NOT silently shorten it — a shortened rendering is
  presentation-only and never a comparison or storage key.
- The address is defined only over **finalized** facets: computing it is a
  post-consolidation operation, and anything that caches identity earlier
  must rekey after finalization.
- The address identifies the **stable occurrence class**, never a per-node
  primary key: occurrences distinguishable only by raw evidence, and
  occurrences whose stripped facets coincide, share an address by design
  and are disambiguated by the graph. An address-keyed store must pair the
  address with a store-local occurrence discriminator or persist such nodes
  at package granularity.

### Worked example

Package identity `pkg:npm/left-pad@1.3.0` with an empty occurrence facet:

```
encoding = 0000000d "bomly:node:v1"
           00000016 "pkg:npm/left-pad@1.3.0"
           00000000
         = 0000000d 626f6d6c793a6e6f64653a7631
           00000016 706b673a6e706d2f6c6566742d70616440312e332e30
           00000000
```

The address is the first 16 bytes of the SHA-256 of those bytes, lowercase
hex: `62b325a01a10705a6dd3235895830e1c` — pinned, with this exact vector
(`purl-empty-facet`), in `testdata/identity_vectors.json`.

## 5. Ephemeral discriminators (never persisted)

Before consolidation, a graph insertion that would collide two records with
contradicting resolutions keeps the second alive under:

```
ephemeral-id = base NUL "o" nonzero-digit *digit
```

NUL (0x00) can never appear in a readable ID, so the families are
structurally disjoint. The ephemeral form is explicitly non-normative for
persistence: it may cross in-process and intra-run plugin-wire boundaries,
but MUST NOT reach a user-visible document or persistent store —
finalization folds or replaces every ephemeral record first.

## 6. Evolution

The facet set and encoding evolve only by minting a new version tag
(`bomly:node:v2`) and encoder beside v1 — never by changing what existing
addresses hash over. Adding a key to the identity-qualifier allowlist
changes derived package identities and therefore rides a version bump of
the identity spec, with regenerated vectors.
