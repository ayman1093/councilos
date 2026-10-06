# councilos

[![CI](https://github.com/ayman1093/councilos/actions/workflows/ci.yml/badge.svg)](https://github.com/ayman1093/councilos/actions/workflows/ci.yml)

**Governed, replayable execution kernel for AI agents.**

Every instruction goes through:

```
policy → capability → resource lease → execution → event → evidence → state
```

Any session can be replayed from its event log to the same hashes — **without the model present**.

The promise is **auditable replay**, not full determinism.

## Current Status: M0 (Silent Skeleton)

- Data contracts and hashing rules only
- No scheduler, no runtime, no I/O, no policy engine yet
- Strict determinism guardrails (no HashMap/HashSet, no floats in hashable state)
- Golden hashes + cross-process determinism tests
- CI on Linux, macOS and Windows with pinned Rust toolchain

## Why this exists

Most AI agent frameworks focus on **capability**.
Very few focus on **governance, auditability, and exact replay**.

This kernel is built for environments where you need to answer:

> *"What exactly did the agent do — and can we prove it?"*

## Quick Links

- [Architecture Decision Record (ADR-0001)](docs/adr/0001-canonical-serialization.md)
- [M1 Specification — The Deterministic Core](docs/specs/M1.md)
- [Engineering rules for AI assistants](CLAUDE.md)
- [Security policy](SECURITY.md)

## Roadmap

- **M0** — silent skeleton: data contracts + hashing ✅
- **M1** — deterministic core: NOP through the full governed path + replay
- **M2** — limited expansion (EmitEvent, ReadState, sequential queue)
- **0.1 → 0.7** — kernel → first agent → first LLM driver → memory → multi-agent

## Build & test

Requires Rust 1.75+.

```
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test
```

Print golden hashes:

```
cargo test --test m0_golden -- --nocapture | grep '^GOLDEN:'
```

## License

Apache-2.0
