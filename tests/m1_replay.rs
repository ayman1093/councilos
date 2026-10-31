//! M1 replay acceptance tests: Gate A's experimental bridge and its teeth.
//!
//! What this file proves, mapped one by one to the signed P1.5 judgements:
//!
//! 1. The property, count and space both as signed: 1024 random byte
//!    streams, each a complete scenario — live execution through a written
//!    host, a write to the real store, then a load, a replay, and the
//!    final-state comparison. The byte is the only generator
//!    (a vector of up to seven arbitrary bytes); its meaning is plain Rust
//!    in the test body: `% 3 == 0` commits a NOP through a host that
//!    returns the frozen payload, `== 1` crashes with a signal drawn
//!    deterministically from {SIGABRT, SIGKILL, SIGSEGV} — the real
//!    signals the subprocess suite observes from `wait` itself — and `== 2` is
//!    refused by gate C before the host is ever consulted. The zero-length
//!    case is the header-only session: derived genesis, `verified_pairs == 0`.
//! 2. The `HashMismatch` tooth: the last record's `state_hash`, one hex
//!    digit of its digest changed to another valid digit. The store's own
//!    structural checks pass it — nothing follows the last record — so the
//!    fold alone can notice, and the recomputation fires the tooth at the
//!    sequence of that record. A middle record tampered this way
//!    never gets that far: the next record's `prev_hash` check catches it
//!    as `ChainMismatch` from load — correct store behavior, hence this tooth.
//! 3. The two `PolicyMismatch` teeth: a single divergent `policy_set_hash`
//!    explodes in `load` itself — the intra-session tooth alive since P1.3,
//!    re-anchored here through the replay entry point deliberately; and a
//!    uniformly foreign hash passes load untouched and dies at sequence
//!    zero against the compiled policy set — the newborn tooth.
//! 4. The two-process crossing of Gate A: one golden session, the child
//!    binary driven through `CARGO_BIN_EXE_m1_replay_child`, its printed
//!    line compared byte for byte with the in-process replay of the same
//!    file — same preimage, same digest, two processes.
//!
//! Scope notes, declared honestly:
//!
//! - No real processes inside the property itself: 1024 spawns would cost
//!   time and invite races; the written host answers on the in-process
//!   route only, and the real crossing is the dedicated child test below.
//! - The closed generation interface: no choice combinators, no
//!   composition, no mapping — the byte generates, branches are plain Rust.
//! - The case count is pinned by the explicit config, not the 256 default;
//!   `PROPTEST_CASES` is unset in the gates, so it cannot drift below 1000.
//! - Wire lines are read and then rewritten as plain text: the tamper teeth are
//!   about bytes on disk that stay structurally valid, which is precisely
//!   what text-level surgery produces.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use councilos_kernel::event_store::{load, EventStore, ReplayError, StoreError};
use councilos_kernel::host::{HandlerHost, HandlerReply, HandlerRequest, HostError};
use councilos_kernel::in_process_host::{InProcessHost, NOP_PAYLOAD};
use councilos_kernel::instruction::{Instruction, NOP_KIND};
use councilos_kernel::policy::PolicySet;
use councilos_kernel::replay::{replay_session, ReplaySessionError};
use councilos_kernel::runtime::Runtime;
use councilos_kernel::state::{canonical, CanonicalState, CanonicalValue, HashAlg};
use proptest::prelude::*;

/// Session name for every single session file this suite creates.
const SESSION: &str = "m1-replay";

/// SIGABRT on Linux — documented locally here, no `libc` dependency.
const SIGABRT: i32 = 6;

/// SIGKILL on Linux — documented locally here, no `libc` dependency.
const SIGKILL: i32 = 9;

/// SIGSEGV on Linux — documented locally here, no `libc` dependency.
const SIGSEGV: i32 = 11;

/// The three crash signals a byte can ask for: real, wait-observed values.
const CRASH_SIGNALS: [i32; 3] = [SIGABRT, SIGKILL, SIGSEGV];

/// Path of the replay child binary, placed by Cargo for the integration tests.
const REPLAY_CHILD: &str = env!("CARGO_BIN_EXE_m1_replay_child");

/// Unwrap a `Result` without `expect`/`unwrap`, reporting what just failed.
fn must_ok<T, E: std::fmt::Display>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{what} failed: {error}"),
    }
}

/// Unique session path per test: process id plus a static atomic counter.
fn temp_path(tag: &str) -> PathBuf {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    std::env::temp_dir().join(format!("councilos-m1-replay-{tag}-{pid}-{id}.jsonl"))
}

/// The genesis template with this suite's own session name: exactly what a
/// live caller seeds and what replay derives from the header, so the two
/// agree by construction whenever the two names match.
fn initial_state() -> CanonicalState {
    let mut state = CanonicalState::new();
    state.insert("session".to_string(), CanonicalValue::Str(SESSION.to_string()));
    state.insert("nop_count".to_string(), CanonicalValue::Int(0));
    state.insert("last_sequence".to_string(), CanonicalValue::Int(0));
    state
}

/// Canonical JSON of a state, through the crate's very own frozen serializer.
fn state_json(state: &CanonicalState) -> String {
    match canonical(state) {
        Ok(value) => value.to_canonical_json(),
        Err(_) => panic!("the state must always canonicalize"),
    }
}

/// The crash signal that one byte encodes: deterministic, drawn from the
/// documented set, so the same byte always asks for the same signal.
fn crash_signal(byte: u8) -> i32 {
    CRASH_SIGNALS[(usize::from(byte) / 3) % 3]
}

/// The gate-C rejection instruction: a NOP body under a capability that the
/// fixed policy set does not carry.
fn denied_instruction() -> Instruction {
    Instruction {
        kind: NOP_KIND.to_string(),
        capability: "state.write".to_string(),
        args: CanonicalValue::Map(BTreeMap::new()),
    }
}

/// The written host of the whole property: one scripted reply per byte the
/// gate lets through. It holds the full stream and skips gate-C bytes —
/// they never reach `run` — so its answers stay aligned with the byte the
/// runtime is executing. The two host-visible arms are a committed NOP
/// with the frozen payload, or a crash reported exactly as `wait` would
/// have observed it.
struct WrittenHost {
    bytes: Vec<u8>,
    next: usize,
}

impl HandlerHost for WrittenHost {
    fn run(&mut self, _request: &HandlerRequest) -> Result<HandlerReply, HostError> {
        // Gate-C bytes never reach the host: the runtime refuses them at
        // the capability gate before consulting it. Skipping them here
        // keeps the script aligned with the byte being executed right now.
        let byte = loop {
            let byte = match self.bytes.get(self.next) {
                Some(byte) => *byte,
                None => panic!("the scripted host ran out of scripted replies"),
            };
            self.next += 1;
            if byte % 3 != 2 {
                break byte;
            }
        };
        if byte % 3 == 0 {
            Ok(HandlerReply::Finished {
                payload: NOP_PAYLOAD.to_vec(),
            })
        } else {
            Err(HostError::Crashed {
                signal: Some(crash_signal(byte)),
                exit_code: None,
            })
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn random_byte_streams_replay_to_the_live_final_state(
        bytes in proptest::collection::vec(any::<u8>(), 0..8),
    ) {
        let path = temp_path("fuzz");
        let host = WrittenHost { bytes: bytes.clone(), next: 0 };
        let store = must_ok(EventStore::create(&path, SESSION), "create the session store");
        let mut runtime = must_ok(
            Runtime::new(PolicySet, initial_state(), host, store),
            "build the governed runtime",
        );
        for (expected_sequence, byte) in bytes.iter().enumerate() {
            // The enumerate index is the expected dense sequence from
            // zero, cast to u64 losslessly exactly as the store does.
            // Both host-visible arms take the same governed NOP and differ
            // only in what the written host answers with; gate-C bytes
            // need the denied instruction instead, refused by the gate in place.
            let instruction = if *byte % 3 == 2 {
                denied_instruction()
            } else {
                Instruction::nop()
            };
            let event = must_ok(runtime.execute(instruction), "execute one scripted step");
            prop_assert_eq!(event.sequence, expected_sequence as u64);
        }
        let live_json = state_json(runtime.state());
        let live_hash = must_ok(
            canonical(runtime.state()).and_then(|value| value.hash(HashAlg::Blake3)),
            "hash the live final state again",
        );
        drop(runtime);
        let replayed = must_ok(replay_session(&path, PolicySet), "replay the written session");
        prop_assert_eq!(replayed.verified_pairs, bytes.len());
        let mut committed_nops = 0i64;
        prop_assert_eq!(state_json(&replayed.final_state), live_json);
        for byte in &bytes {
            if *byte % 3 == 0 {
                committed_nops += 1;
            }
        }
        prop_assert_eq!(replayed.final_state_hash, live_hash);
        let expected_nops = CanonicalValue::Int(committed_nops);
        prop_assert_eq!(replayed.final_state.get("nop_count"), Some(&expected_nops));
        let _ = std::fs::remove_file(&path);
    }
}

/// The session file's complete wire lines, exactly as the store first
/// wrote them.
fn session_lines(path: &Path) -> Vec<String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(_) => panic!("the session file must always be readable"),
    };
    text.lines().map(|line| line.to_string()).collect()
}

/// Rewrite the whole session file back again from complete lines.
fn rewrite(path: &Path, lines: &[String]) {
    let mut text = lines.join("\n");
    text.push('\n');
    match std::fs::write(path, text.as_bytes()) {
        Ok(()) => {}
        Err(_) => panic!("the session file must always be writable"),
    }
}

/// Exactly one hex digit of `value` changed to a different valid digit, at
/// `position`: the value stays decodable, the bytes it names change.
fn flipped_hex(value: &str, position: usize) -> String {
    let mut digits: Vec<char> = value.chars().collect();
    let original = digits[position];
    digits[position] = match original {
        '0' => '1',
        _ => '0',
    };
    digits.into_iter().collect()
}

/// The quoted value of one single string field of a compact wire
/// line.
fn string_field(line: &str, field: &str) -> String {
    let needle = format!("\"{field}\":\"");
    let start = match line.find(&needle) {
        Some(position) => position + needle.len(),
        None => panic!("the wire line must carry the `{field}` field"),
    };
    let end = match line[start..].find('"') {
        Some(position) => start + position,
        None => panic!("the `{field}` field must be a quoted string"),
    };
    line[start..end].to_string()
}

/// The same wire line once again with exactly one string field's value replaced.
fn with_string_field(line: &str, field: &str, replacement: &str) -> String {
    let current = string_field(line, field);
    line.replacen(
        &format!("\"{field}\":\"{current}\""),
        &format!("\"{field}\":\"{replacement}\""),
        1,
    )
}

/// A two-NOP session on the real store — the golden pattern itself: the
/// in-process host through the runtime, five wire lines for the teeth below.
fn two_nop_session(path: &Path) {
    let store = must_ok(EventStore::create(path, SESSION), "create the session store");
    let mut runtime = must_ok(
        Runtime::new(PolicySet, initial_state(), InProcessHost, store),
        "build the governed runtime",
    );
    must_ok(runtime.execute(Instruction::nop()), "execute the first governed nop");
    must_ok(runtime.execute(Instruction::nop()), "execute the second governed nop");
}

#[test]
fn tampered_last_state_hash_surfaces_as_hash_mismatch_from_replay() {
    let path = temp_path("hash-tooth");
    two_nop_session(&path);
    let lines = session_lines(&path);
    assert_eq!(lines.len(), 5, "header plus two event/record pairs");
    // The last record is the only one that no successor ever inspects: flipping
    // one digest digit (past the four schema/alg nibbles) keeps the whole
    // file structurally valid for the store to accept and pass.
    let last = lines.len() - 1;
    let tampered = with_string_field(
        &lines[last],
        "state_hash",
        &flipped_hex(&string_field(&lines[last], "state_hash"), 4),
    );
    let mut rewritten = lines;
    rewritten[last] = tampered;
    rewrite(&path, &rewritten);
    let session = must_ok(load(&path), "load the tampered session file");
    assert_eq!(session.pairs.len(), 2, "both pairs still parse");
    match replay_session(&path, PolicySet) {
        Err(ReplaySessionError::Replay(ReplayError::HashMismatch { sequence })) => {
            assert_eq!(sequence, 1, "tampered pair");
        }
        _ => panic!("a tampered last state hash must fire from the fold, never from the store"),
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn divergent_policy_set_hash_surfaces_from_load_before_replay() {
    let path = temp_path("policy-store");
    two_nop_session(&path);
    let lines = session_lines(&path);
    assert_eq!(lines.len(), 5, "header plus two event/record pairs");
    // One event's policy hash diverges from its own sibling's: the store's
    // own intra-session tooth, alive since P1.3, fires before any replay can
    // start folding even one single pair.
    let tampered = with_string_field(
        &lines[3],
        "policy_set_hash",
        &flipped_hex(&string_field(&lines[3], "policy_set_hash"), 4),
    );
    let mut rewritten = lines;
    rewritten[3] = tampered;
    rewrite(&path, &rewritten);
    match replay_session(&path, PolicySet) {
        Err(ReplaySessionError::Store(StoreError::Integrity(ReplayError::PolicyMismatch {
            sequence,
        }))) => {
            assert_eq!(sequence, 1, "tampered pair");
        }
        _ => panic!("a divergent policy hash must fire from load itself, before any folding"),
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn uniformly_foreign_policy_set_surfaces_as_policy_mismatch_at_sequence_zero() {
    let path = temp_path("policy-replay");
    two_nop_session(&path);
    let lines = session_lines(&path);
    assert_eq!(lines.len(), 5, "header plus two event/record pairs");
    // Every single event carries one foreign but valid policy hash: internally
    // fully consistent, so load passes; the compiled policy set still disagrees
    // at the very first event — the newborn replay tooth of the fold.
    let foreign = flipped_hex(&string_field(&lines[1], "policy_set_hash"), 4);
    let first = with_string_field(&lines[1], "policy_set_hash", &foreign);
    let second = with_string_field(&lines[3], "policy_set_hash", &foreign);
    let mut rewritten = lines;
    rewritten[1] = first;
    rewritten[3] = second;
    rewrite(&path, &rewritten);
    let session = must_ok(load(&path), "load the consistent session");
    assert_eq!(session.pairs.len(), 2, "both pairs still parse");
    match replay_session(&path, PolicySet) {
        Err(ReplaySessionError::Replay(ReplayError::PolicyMismatch { sequence })) => {
            assert_eq!(sequence, 0, "the first pair");
        }
        _ => panic!("a uniformly foreign policy set must die at sequence zero of the fold"),
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn two_processes_agree_on_the_final_state_hash() {
    let path = temp_path("child");
    let store = must_ok(EventStore::create(&path, SESSION), "create the session store");
    let mut runtime = must_ok(
        Runtime::new(PolicySet, initial_state(), InProcessHost, store),
        "build the governed runtime",
    );
    must_ok(runtime.execute(Instruction::nop()), "execute the governed nop");
    let live_hash = must_ok(
        canonical(runtime.state()).and_then(|value| value.hash(HashAlg::Blake3)),
        "hash the live final state again",
    );
    drop(runtime);
    let in_process = must_ok(replay_session(&path, PolicySet), "replay in the parent process");
    assert_eq!(in_process.final_state_hash, live_hash);
    let output = must_ok(
        Command::new(REPLAY_CHILD).arg(&path).output(),
        "run the replay child",
    );
    assert!(
        output.status.success(),
        "the child must exit zero after printing its final state hash"
    );
    let stdout = must_ok(String::from_utf8(output.stdout), "decode the child's own stdout line");
    assert_eq!(stdout.trim_end(), in_process.final_state_hash.to_hex());
    let _ = std::fs::remove_file(&path);
}
