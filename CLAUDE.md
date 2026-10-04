


# CLAUDE.md — Engineering rules for AI assistants working on councilos-kernel

Read this fully before touching any file.

## Project identity

Governed, replayable execution kernel for AI agents (Rust).
Promise: **auditable replay**, not "full determinism".
Current state: M0 (silent skeleton) complete and green.
Next: M1 (deterministic core). See docs/adr/0001 and tests/m0_golden.rs.

## Hard rules (violating any of these = reject your own output)

1. **Spec > Code.** If code conflicts with a documented decision,
   the code is wrong. Never silently change a settled decision.
2. **Golden hashes are frozen.** Never update a value in
   tests/m0_golden.rs to make a test pass. If a golden changed,
   the canon changed → requires SCHEMA_VERSION bump + new goldens.
3. **No HashMap/HashSet/f32/f64** anywhere in this crate
   (enforced by clippy.toml — BTreeMap/BTreeSet only).
4. **No wall-clock time or randomness inside hashable state.**
   recorded_at_unix_ms is metadata, excluded from every hash.
5. **Runtime signs evidence; agents never sign their own.**
6. **Sequence, not UUID.** Ordering is by sequence: u64.
7. **`cargo build && cargo clippy --all-targets --locked -- -D warnings
   && cargo test` must pass** before claiming any task is done.
   "It should compile" is not done. Run it or say you can't.
8. **No new docs/files before working code.** (Project principle P53:
   systems evolve through implementation, not philosophy.)
   New RFCs, wikis, or "vision" files require explicit approval.
9. **Scope discipline:** implement ONLY the requested milestone/issue.
   Never implement future milestones. Never invent architecture.
10. **Every non-trivial implementation decision goes in an ADR**
    (docs/adr/NNNN-*.md) in the same commit, or is documented
    in the PR description.

## The verification loop (how work happens here)

write → run → paste actual errors verbatim → fix → repeat.
Never guess at compiler output. Never claim a fix without a run.
If you cannot execute code (no sandbox), say so and produce code
marked as "unverified — needs CI".

## Known constraints (do not reopen without an ADR)

- M1 is fully synchronous — no tokio (revisit at 0.2+ via ADR only).
- BLAKE3 (0x01) only in M0; SHA-256 (0x02) reserved for FIPS,
  not linked. Hash layout: [schema_version][alg][digest; 32].
- Known issue (ADR-0002 pending): direct construction of
  CanonicalValue::Map can bypass the `$`-key rule. Do not "fix"
  this casually — it changes canonical semantics.

## Layout

- src/ — the crate (instruction, event, state, hex, lib)
- tests/m0_golden.rs — golden pinning (treat as read-only contract)
- docs/adr/ — decision records (read before changing anything canonical)
- clippy.toml — determinism guardrails (extends these rules)


