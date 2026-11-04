//! M1 subprocess acceptance tests: the governed path against a real child
//! process, the true Gate B (SIGABRT raised by the operating system), the
//! signed D7 reply path (declared length above the limit → SIGKILL), and
//! the three remaining `SpawnFailed` teeth on the subprocess route.
//!
//! What this file proves, mapped to the signed teeth:
//!
//! 1. POSIX wait — the observed `wait` status is the single source of truth
//!    for a death; the two `Crashed` shapes below come straight from it.
//! 2. `event.rs:52` ("Recorded, never raised") — a dying handler yields an
//!    `Event` through `Runtime::execute`, never an `Err`, and the session
//!    line itself records the crash.
//! 3. `docs/specs/M1.md:38` / `M1.md:40` — crashes are recorded events, and
//!    infrastructure errors surface as `Err(SpawnFailed)`.
//!
//! The fourth tooth (clean re-entry after a spawn failure) was closed in
//! P1.3 with a scripted host; it is re-proven here on the subprocess route
//! without claiming duplication: the same runtime fails once, consumes no
//! sequence, then commits a real child's reply with sequence zero.
//!
//! Scope notes, declared honestly:
//!
//! - No `{:?}`/`{}` formatting of `Event` or `HandlerOutcome` anywhere:
//!   crash evidence is read from the session file's text, and assertions
//!   use `assert_eq!` only on types whose derives are frozen (`HostError`,
//!   strings, integers).
//! - `evidence_ref` is not recomputed here: its preimage contract is frozen
//!   by `tests/m1_policy.rs`, and the subprocess route adds no new hashing —
//!   the child only has to return the frozen payload byte for byte.
//! - Spawn failures use a scripted first failure plus a real child: the
//!   production host cannot make a missing program appear, and flipping
//!   environment variables between parallel tests would be a race.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use councilos_kernel::event_store::{load, EventStore};
use councilos_kernel::host::{HandlerHost, HandlerReply, HandlerRequest, HostError};
use councilos_kernel::in_process_host::NOP_PAYLOAD;
use councilos_kernel::instruction::Instruction;
use councilos_kernel::policy::PolicySet;
use councilos_kernel::runtime::{Runtime, RuntimeError};
use councilos_kernel::state::{canonical, CanonicalState, CanonicalValue};
use councilos_kernel::subprocess_host::SubprocessHost;

/// Session name for every file this suite creates.
const SESSION: &str = "m1-subprocess";

/// Canonical initial state, frozen byte-exact.
const INITIAL_STATE_CANONICAL: &str =
    "{\"last_sequence\":0,\"nop_count\":0,\"session\":\"m1-subprocess\"}";

/// Canonical state after one committed NOP.
const FINAL_STATE_CANONICAL: &str =
    "{\"last_sequence\":0,\"nop_count\":1,\"session\":\"m1-subprocess\"}";

/// Canonical state after a recorded crash and then one committed NOP.
const CRASH_THEN_NOP_STATE_CANONICAL: &str =
    "{\"last_sequence\":1,\"nop_count\":1,\"session\":\"m1-subprocess\"}";

/// SIGABRT on Linux — documented locally, no `libc` dependency.
const SIGABRT: i32 = 6;

/// SIGKILL on Linux — documented locally, no `libc` dependency.
const SIGKILL: i32 = 9;

/// Path of the NOP child, placed by Cargo for integration tests.
const NOP_CHILD: &str = env!("CARGO_BIN_EXE_m1_nop_child");

/// Path of the abort child, placed by Cargo for integration tests.
const ABORT_CHILD: &str = env!("CARGO_BIN_EXE_m1_abort_child");

/// Path of the bad-frame child, placed by Cargo for integration tests.
const BAD_FRAME_CHILD: &str = env!("CARGO_BIN_EXE_m1_bad_frame_child");

/// Unwrap a `Result` without `expect`/`unwrap`, reporting no payload.
fn must_ok<T, E>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(_) => panic!("expected Ok from the crate API"),
    }
}

/// Unique session path per test: process id plus a static counter.
fn temp_path() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "councilos-m1-subprocess-{}-{n}.jsonl",
        std::process::id()
    ))
}

/// The frozen initial state as a `CanonicalState`.
fn initial_state() -> CanonicalState {
    let mut state = CanonicalState::new();
    state.insert("last_sequence".to_string(), CanonicalValue::Int(0));
    state.insert("nop_count".to_string(), CanonicalValue::Int(0));
    state.insert("session".to_string(), CanonicalValue::Str(SESSION.to_string()));
    state
}

/// Canonical JSON of a state, through the crate's frozen serializer.
fn state_json(state: &CanonicalState) -> String {
    match canonical(state) {
        Ok(value) => value.to_canonical_json(),
        Err(_) => panic!("state must canonicalize"),
    }
}

/// Session text, read after the store has finished writing.
fn session_text(path: &Path) -> String {
    match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(_) => panic!("session file must be readable"),
    }
}

/// What a store wrote: number of stored event/record pairs.
fn pair_count(path: &Path) -> usize {
    must_ok(load(path)).pairs.len()
}

/// Match `"field":value` allowing one space after the colon: the JSONL
/// envelope is wire-only, and its spacing is not part of any preimage.
fn text_has_number_field(text: &str, field: &str, value: i32) -> bool {
    let compact = format!("\"{field}\":{value}");
    let spaced = format!("\"{field}\": {value}");
    text.contains(&compact) || text.contains(&spaced)
}

/// Fails the first call with `Io` (a spawn failure), then delegates to a
/// real child — the clean-re-entry tooth on the subprocess route.
struct FailOnceThenSubprocess {
    failures_left: u32,
    program: PathBuf,
}

impl HandlerHost for FailOnceThenSubprocess {
    fn run(&mut self, request: &HandlerRequest) -> Result<HandlerReply, HostError> {
        if self.failures_left > 0 {
            self.failures_left -= 1;
            return Err(HostError::Io {
                reason: "scripted spawn failure".to_string(),
            });
        }
        SubprocessHost::new(self.program.clone()).run(request)
    }
}

/// Delegates each call to the next scripted child program.
struct SequentialHost {
    programs: Vec<PathBuf>,
    index: usize,
}

impl HandlerHost for SequentialHost {
    fn run(&mut self, request: &HandlerRequest) -> Result<HandlerReply, HostError> {
        let program = match self.programs.get(self.index) {
            Some(program) => program.clone(),
            None => panic!("scripted host exhausted"),
        };
        self.index += 1;
        SubprocessHost::new(program).run(request)
    }
}

/// Build a governed runtime around `host` that writes to `path`.
fn runtime_with<H: HandlerHost>(host: H, path: &Path) -> Runtime<H> {
    let store = must_ok(EventStore::create(path, SESSION));
    must_ok(Runtime::new(PolicySet, initial_state(), host, store))
}

/// One `HandlerRequest` carrying the frozen NOP instruction.
fn nop_request() -> HandlerRequest {
    HandlerRequest {
        instruction: Instruction::nop(),
        deadline_ms: 0,
    }
}

#[test]
fn nop_child_returns_the_frozen_payload() {
    let mut host = SubprocessHost::new(NOP_CHILD);
    match host.run(&nop_request()) {
        Ok(HandlerReply::Finished { payload }) => {
            assert_eq!(payload.as_slice(), NOP_PAYLOAD);
        }
        _ => panic!("the NOP child must return the frozen payload"),
    }
}

#[test]
fn nop_child_through_runtime_commits_frozen_state() {
    let path = temp_path();
    let mut runtime = runtime_with(SubprocessHost::new(NOP_CHILD), &path);
    let event = must_ok(runtime.execute(Instruction::nop()));
    assert_eq!(event.sequence, 0);
    assert_eq!(state_json(runtime.state()), FINAL_STATE_CANONICAL);
    let session = must_ok(load(&path));
    assert_eq!(session.name, SESSION);
    assert_eq!(session.pairs.len(), 1);
    assert_eq!(session.pairs[0].event.sequence, 0);
    assert!(session.pairs[0].record.prev_hash.is_none());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn gate_b_sigabrt_is_recorded_as_an_event_not_raised() {
    let path = temp_path();
    let mut runtime = runtime_with(SubprocessHost::new(ABORT_CHILD), &path);
    let event = must_ok(runtime.execute(Instruction::nop()));
    assert_eq!(event.sequence, 0);
    assert_eq!(state_json(runtime.state()), INITIAL_STATE_CANONICAL);
    let text = session_text(&path);
    assert!(text.contains("crashed"));
    assert!(text_has_number_field(&text, "signal", SIGABRT));
    assert_eq!(pair_count(&path), 1);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn abort_child_is_observed_as_sigabrt_from_wait() {
    let mut host = SubprocessHost::new(ABORT_CHILD);
    match host.run(&nop_request()) {
        Err(HostError::Crashed { signal, exit_code }) => {
            assert_eq!(signal, Some(SIGABRT));
            assert_eq!(exit_code, None);
        }
        _ => panic!("a real SIGABRT must be reported exactly as wait observed it"),
    }
}

#[test]
fn d7_oversized_reply_is_sigkilled_as_observed_from_wait() {
    let mut host = SubprocessHost::new(BAD_FRAME_CHILD);
    match host.run(&nop_request()) {
        Err(HostError::Crashed { signal, exit_code }) => {
            assert_eq!(signal, Some(SIGKILL));
            assert_eq!(exit_code, None);
        }
        _ => panic!("an over-limit reply must be SIGKILLed and reported as observed"),
    }
}

#[test]
fn d7_oversized_reply_through_runtime_records_crash_with_sequence_zero() {
    let path = temp_path();
    let mut runtime = runtime_with(SubprocessHost::new(BAD_FRAME_CHILD), &path);
    let event = must_ok(runtime.execute(Instruction::nop()));
    assert_eq!(event.sequence, 0);
    assert_eq!(state_json(runtime.state()), INITIAL_STATE_CANONICAL);
    let text = session_text(&path);
    assert!(text.contains("crashed"));
    assert!(text_has_number_field(&text, "signal", SIGKILL));
    assert_eq!(pair_count(&path), 1);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn spawn_failure_surfaces_spawn_failed_and_reentry_uses_sequence_zero() {
    let path = temp_path();
    let host = FailOnceThenSubprocess {
        failures_left: 1,
        program: PathBuf::from(NOP_CHILD),
    };
    let mut runtime = runtime_with(host, &path);
    match runtime.execute(Instruction::nop()) {
        Err(RuntimeError::SpawnFailed { .. }) => {}
        _ => panic!("a spawn failure must surface as SpawnFailed, never as an event"),
    }
    assert_eq!(state_json(runtime.state()), INITIAL_STATE_CANONICAL);
    assert_eq!(pair_count(&path), 0);
    let event = must_ok(runtime.execute(Instruction::nop()));
    assert_eq!(event.sequence, 0);
    assert_eq!(state_json(runtime.state()), FINAL_STATE_CANONICAL);
    assert_eq!(pair_count(&path), 1);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn crash_then_nop_consumes_dense_sequences() {
    let path = temp_path();
    let host = SequentialHost {
        programs: vec![PathBuf::from(ABORT_CHILD), PathBuf::from(NOP_CHILD)],
        index: 0,
    };
    let mut runtime = runtime_with(host, &path);
    let crashed = must_ok(runtime.execute(Instruction::nop()));
    assert_eq!(crashed.sequence, 0);
    assert_eq!(state_json(runtime.state()), INITIAL_STATE_CANONICAL);
    let committed = must_ok(runtime.execute(Instruction::nop()));
    assert_eq!(committed.sequence, 1);
    assert_eq!(state_json(runtime.state()), CRASH_THEN_NOP_STATE_CANONICAL);
    let session = must_ok(load(&path));
    assert_eq!(session.pairs.len(), 2);
    assert_eq!(session.pairs[0].event.sequence, 0);
    assert_eq!(session.pairs[1].event.sequence, 1);
    let _ = std::fs::remove_file(&path);
}
