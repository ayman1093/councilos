councilos-kernel
CI

A governed, replayable execution kernel for AI agents, written in Rust.

Every instruction passes through policy → capability → resource lease → execution → event → evidence → state, and any session can be replayed from its event log to the same hashes — without the model present.

The promise is auditable replay, not "full determinism".

Current state: M0 (silent skeleton)
Data contracts and hashing rules only. No scheduler, no runtime, no I/O, no policy engine.

CI verifies (all green):

Build (13 files, zero warnings under -D warnings)
Clippy with determinism guardrails: no HashMap/HashSet/floats in hashable state (see clippy.toml)
Unit tests for every module
Golden hashes pinned byte-exact (tests/m0_golden.rs)
Cross-process determinism: golden tests run twice in separate processes and diffed — identical hashes
Build & test
cargo fmt --all -- --checkcargo clippy --all-targets -- -D warningscargo testcargo test --test m0_golden -- --nocapture | grep '^GOLDEN:'  # print golden hashes
Architecture decisions
See docs/adr/0001-canonical-serialization.md —canonical JSON (schema 0), BLAKE3 with versioned layout [schema][alg][digest],BTreeMap-only ordering, sequence-not-UUID, time-as-metadata.

Roadmap
M0 — silent skeleton: data contracts + hashing ✅
M1 — deterministic core: NOP through the full governed path + replay
M2 — limited expansion (EmitEvent, ReadState, sequential queue)
Then versions 0.1 → 0.7 (kernel → first agent → first LLM driver → memory → multi-agent)
License
Apache-2.0 
