# ADR-0001: Canonical serialization and hash layout

- Status: **Accepted** (consensus of 4 independent model reviews; do not reopen)
- Milestone: M0 (schema 0), M1 (schema 1)
- Enforced by: `src/state.rs`, `clippy.toml`, `tests/m0_golden.rs`

## Context

Every instruction, event and state in CouncilOS must be hashable so that a session
can be replayed from its event log and produce the same hashes without the model
present. Auditors in regulated sectors must also be able to *read* the log. These
two needs pull in different directions: readability wants JSON; hashing wants a
byte-exact canonical form.

## Decision

1. **Wire format: JSON.** Everything stored or transmitted is JSON so an auditor
   can read it with no tooling.
2. **Hash preimage, schema 0 (M0): canonical JSON.** Compact (no whitespace),
   object keys sorted bytewise, integers in shortest decimal form, strings
   escaped exactly as `serde_json` escapes them, bytes as `{"$bytes":"<hex>"}".
   The preimage is produced by `CanonicalValue::to_canonical_json`, never by
   serde field order.
3. **Hash preimage, schema 1 (M1): Deterministic CBOR** (RFC 8949 §4.2). Schema 0
   remains implemented forever for replaying M0 sessions.
4. **Hash layout:** `[schema_version: u8][alg: u8][digest: 32 bytes]`, printed as
   68 lowercase hex characters. The two header bytes are also fed into the hash
   *before* the preimage, so a digest is bound to its declared version and
   algorithm.
5. **Algorithms:** `0x01` = BLAKE3 (default). `0x02` = SHA-256, reserved for
   FIPS-constrained clients; declared but not linked in M0.
6. **Value universe:** null, bool, i64, bytes, string, sequence, map with string
   keys. **No floats** — budgets are integer milli-units in a separate ledger.
   **No `HashMap`/`HashSet`** anywhere in the kernel (random iteration order);
   `BTreeMap`/`BTreeSet` only. No wall-clock time or randomness inside anything
   hashable; `Event.recorded_at_unix_ms` is metadata and is excluded from hashes.
   Ordering is by `sequence: u64`, never UUID.

## Alternatives rejected

- **Protobuf** — serialization is not formally deterministic (unknown fields, map
  ordering, implementation-defined varint choices across languages).
- **Hash serde output directly** — field order depends on struct declaration
  order and `skip_serializing_if`; a refactor would silently change hashes.
- **UUIDs for ordering** — not replayable, not dense, adds randomness.

## Versioning and migration

- `SCHEMA_VERSION` is a crate constant. A change to any canonical rule is a
  **new schema version**, never an edit of an existing one.
- Golden hashes for each schema live in `tests/` and are never updated in place:
  `canonical_v1` stays, `canonical_v2` is *added* with its own goldens.
- A hash's first byte tells the verifier which canonical path to use;
  mixed-version logs are therefore replayable.

## Known limitations (documented, M1 backlog)

- Direct construction of `CanonicalValue::Map` can bypass the `$`-key rule
  (independent-review finding). Resolution: recursive validation at the
  canonical boundary, or a checked constructor as the only path — ADR-0002.
- `sequence as i64` in `StateRecord::to_canonical` wraps past `i64::MAX`
  (theoretical; refused at `Event::to_canonical` instead of wrapping silently).
