
# councilos-kernel

A governed, replayable execution kernel for AI agents, written in Rust.

Every instruction passes through `policy → capability → resource lease → execution → event → evidence → state`, and any session can be replayed from its event log to the same hashes — without the model present.

The promise is **auditable replay**, not "full determinism".

**M0 (this repo today) is a silent skeleton:** data contracts and hashing rules only. No scheduler, no runtime, no I/O, no policy engine.

See [`docs/adr/0001-canonical-serialization.md`](docs/adr/0001-canonical-serialization.md).

## Build & test

    cargo fmt --all -- --check
    cargo clippy --all-targets -- -D warnings
    cargo test
    cargo test --test m0_golden -- --nocapture | grep '^GOLDEN:'  # print golden hashes

## License

Apache-2.0
