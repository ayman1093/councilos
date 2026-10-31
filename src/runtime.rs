//! The governed execution path: one instruction through policy, capability,
//! resource lease, execution, event, evidence and state commit (P1.3).
//!
//! Per-call order (binding):
//!
//! 1. The sequence number is captured from `next_sequence` before anything is
//!    built or carried (`event_store.rs:109`: "Dense, runtime-assigned
//!    position in the log. Starts at 0." — D9).
//! 2. The capability gate evaluates the instruction against the fixed policy
//!    before any execution (Gate C). A rejection is recorded as an event with
//!    [`HandlerOutcome::Rejected`] (`event.rs:47`: "refused the instruction
//!    **before execution**") and commits the unchanged state.
//! 3. A resource lease is acquired (D8). `Lease::acquire` cannot fail in M1.
//! 4. The host executes (`host.rs:107-109`).
//! 5. The host result is mapped to a recorded outcome. Crashes are events,
//!    never exceptions (`event.rs:52`: "Recorded, never raised." — `M1.md:38`).
//! 6. On completion the lease is checked post-hoc (M1 is fully synchronous,
//!    no pre-emption — `M1.md:36`); an expired lease records `TimedOut` and
//!    commits no execution effects.
//! 7. Evidence is the Blake3 digest of the raw payload bytes exactly as
//!    emitted (`host.rs:48-52`: "the bytes here are the bytes hashed" — D15).
//!    Only the digest enters the log; the payload is never stored (D18).
//! 8. Event and state record are appended as one pair by the store, and only
//!    then do in-memory counters advance (D17).
//!
//! Honest limits:
//!
//! - `HostError::Protocol` maps here to `Crashed { signal: None, exit_code: None }`.
//!   Its only producer in P1.3 is `InProcessHost` panic isolation — a caught
//!   panic inside this process. D7's `SIGKILL = 9` mapping to
//!   `Crashed { signal: Some(9), exit_code: None }` is `SubprocessHost`'s
//!   contract in P1.4 (`host.rs:62-72`). This mapping does **not** serve
//!   Gate B: Gate B requires a real `abort()` in a real process.
//! - The protocol reason is written to stderr and never to the log
//!   (`host.rs:66-67`; surfaced, never swallowed — `M1.md:40`).
//! - `HostError::Timeout` is never produced by M1 hosts (`host.rs:90-96`);
//!   the arm exists because the boundary enum is signed.
//! - Infrastructure failures (store I/O, hashing, record construction) abort
//!   the call with `Err(RuntimeError)`. They are not events: no event exists,
//!   so no sequence is consumed and the next call reuses the number. A host
//!   I/O failure is `RuntimeError::SpawnFailed { reason }` (D17): the process
//!   never started, the lease is released by scope exit, and a clean re-entry
//!   is possible.
//! - The store header's session name and the state's `session` key are
//!   independent in M1; `EventStore` keeps no session field to cross-check
//!   (`event_store.rs:255-260`).

use crate::clock;
use crate::event::{Event, HandlerOutcome};
use crate::event_store::{EventStore, StoreError};
use crate::host::{HandlerHost, HandlerReply, HandlerRequest, HostError};
use crate::instruction::{Instruction, NOP_CAPABILITY, NOP_KIND};
use crate::lease::{Lease, NOP_LEASE_MS};
use crate::policy::PolicySet;
use crate::state::{CanonicalState, CanonicalValue, HashAlg, StateHash, StateRecord};
use crate::{Hash32, SCHEMA_VERSION};

/// A governed-path failure.
///
/// Infrastructure failures are surfaced to the caller, never swallowed, and
/// consume no sequence number. Outcomes of an instruction that reached the
/// log are recorded as events instead.
#[derive(Debug)]
pub enum RuntimeError {
    /// The session store refused the append or failed on I/O.
    Store(StoreError),
    /// The fixed policy set could not be hashed.
    PolicyHashUnavailable {
        /// Rendered underlying cause.
        reason: String,
    },
    /// The handler payload could not be hashed into `evidence_ref`.
    EvidenceHashUnavailable {
        /// Rendered underlying cause.
        reason: String,
    },
    /// The committed state record could not be built.
    StateRecordInvalid {
        /// Rendered underlying cause.
        reason: String,
    },
    /// The committed state could not be built from the current state.
    StateBuildInvalid {
        /// Rendered underlying cause.
        reason: String,
    },
    /// The sequence number or its `i64` rendering would overflow.
    SequenceOverflow,
    /// The host failed before the instruction started (D17).
    SpawnFailed {
        /// Human-readable cause from the host boundary.
        reason: String,
    },
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuntimeError::Store(error) => write!(f, "session store failure: {error}"),
            RuntimeError::PolicyHashUnavailable { reason } => {
                write!(f, "policy set hash unavailable: {reason}")
            }
            RuntimeError::EvidenceHashUnavailable { reason } => {
                write!(f, "evidence hash unavailable: {reason}")
            }
            RuntimeError::StateRecordInvalid { reason } => {
                write!(f, "state record invalid: {reason}")
            }
            RuntimeError::StateBuildInvalid { reason } => {
                write!(f, "state build invalid: {reason}")
            }
            RuntimeError::SequenceOverflow => write!(f, "sequence number overflowed"),
            RuntimeError::SpawnFailed { reason } => write!(f, "spawn failed: {reason}"),
        }
    }
}

impl std::error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RuntimeError::Store(error) => Some(error),
            _ => None,
        }
    }
}

/// The governed runtime: fixed policy, host, session store, committed state.
pub struct Runtime<H: HandlerHost> {
    policy: PolicySet,
    policy_set_hash: Hash32,
    state: CanonicalState,
    host: H,
    store: EventStore,
    next_sequence: u64,
    last_record: Option<StateRecord>,
}

impl<H: HandlerHost> Runtime<H> {
    /// Build a runtime over the fixed policy, an initial state, a host and a
    /// freshly created session store.
    ///
    /// The policy hash is computed exactly once here; every event carries the
    /// same digest (`policy.rs:42-53`).
    pub fn new(
        policy: PolicySet,
        initial_state: CanonicalState,
        host: H,
        store: EventStore,
    ) -> Result<Runtime<H>, RuntimeError> {
        let policy_set_hash = policy.hash(HashAlg::Blake3).map_err(|error| {
            RuntimeError::PolicyHashUnavailable {
                reason: format!("{error}"),
            }
        })?;
        Ok(Runtime {
            policy,
            policy_set_hash,
            state: initial_state,
            host,
            store,
            next_sequence: 0,
            last_record: None,
        })
    }

    /// The current committed state.
    pub fn state(&self) -> &CanonicalState {
        &self.state
    }

    /// Execute one instruction through the full governed path.
    ///
    /// Returns the event exactly as appended to the session log. Policy and
    /// host outcomes are recorded events and return `Ok`; only infrastructure
    /// failures return `Err`.
    pub fn execute(&mut self, instruction: Instruction) -> Result<Event, RuntimeError> {
        // D9: captured before anything is built; consumed only with a commit.
        let sequence = self.next_sequence;

        // Gate C: the capability gate runs before execution.
        if !self.policy.permits(&instruction) {
            let reason = format!(
                "capability gate rejected kind `{}` with capability `{}`: the fixed M1 policy grants `{}` on `{}` only",
                instruction.kind, instruction.capability, NOP_CAPABILITY, NOP_KIND
            );
            let unchanged = self.state.clone();
            return self.commit(sequence, instruction, HandlerOutcome::Rejected { reason }, unchanged);
        }

        // D8: time-only lease; acquire cannot fail. Released by scope exit.
        let lease = Lease::acquire();
        let request = HandlerRequest {
            instruction,
            deadline_ms: NOP_LEASE_MS,
        };
        let reply = self.host.run(&request);
        // Partial move after `run` returns: the instruction needs no Clone.
        let instruction = request.instruction;

        match reply {
            Err(HostError::Io { reason }) => Err(RuntimeError::SpawnFailed { reason }),
            Err(HostError::Crashed { signal, exit_code }) => {
                let unchanged = self.state.clone();
                self.commit(
                    sequence,
                    instruction,
                    HandlerOutcome::Crashed { signal, exit_code },
                    unchanged,
                )
            }
            Err(HostError::Protocol { reason }) => {
                // In-process panic isolation: details to stderr, structure to
                // the log (`host.rs:62-72`; D7's SIGKILL(9) is P1.4's mapping).
                eprintln!("host protocol failure: {reason}");
                let unchanged = self.state.clone();
                self.commit(
                    sequence,
                    instruction,
                    HandlerOutcome::Crashed {
                        signal: None,
                        exit_code: None,
                    },
                    unchanged,
                )
            }
            Err(HostError::Timeout) => {
                let unchanged = self.state.clone();
                self.commit(sequence, instruction, HandlerOutcome::TimedOut, unchanged)
            }
            Ok(HandlerReply::Finished { payload }) => {
                if lease.expired() {
                    let unchanged = self.state.clone();
                    return self.commit(
                        sequence,
                        instruction,
                        HandlerOutcome::TimedOut,
                        unchanged,
                    );
                }
                let evidence_ref =
                    StateHash::compute(SCHEMA_VERSION, HashAlg::Blake3, payload.as_slice())
                        .map_err(|error| RuntimeError::EvidenceHashUnavailable {
                            reason: format!("{error}"),
                        })?
                        .digest;
                let mut committed = self.state.clone();
                let previous = match committed.get("nop_count") {
                    None => 0,
                    Some(CanonicalValue::Int(value)) => *value,
                    Some(_) => {
                        return Err(RuntimeError::StateBuildInvalid {
                            reason: "existing `nop_count` is not an integer".to_string(),
                        });
                    }
                };
                let next_count =
                    previous
                        .checked_add(1)
                        .ok_or_else(|| RuntimeError::StateBuildInvalid {
                            reason: "`nop_count` overflowed i64".to_string(),
                        })?;
                let sequence_i64 =
                    i64::try_from(sequence).map_err(|_| RuntimeError::SequenceOverflow)?;
                committed.insert("nop_count".to_string(), CanonicalValue::Int(next_count));
                committed.insert(
                    "last_sequence".to_string(),
                    CanonicalValue::Int(sequence_i64),
                );
                self.commit(
                    sequence,
                    instruction,
                    HandlerOutcome::Completed { evidence_ref },
                    committed,
                )
            }
        }
    }

    /// Record one event+record pair and advance the committed pointers.
    fn commit(
        &mut self,
        sequence: u64,
        instruction: Instruction,
        outcome: HandlerOutcome,
        committed_state: CanonicalState,
    ) -> Result<Event, RuntimeError> {
        let event = Event {
            sequence,
            recorded_at_unix_ms: clock::unix_ms(),
            instruction,
            outcome,
            policy_set_hash: self.policy_set_hash,
        };
        let record = StateRecord::new(
            sequence,
            &committed_state,
            self.last_record.as_ref(),
            HashAlg::Blake3,
        )
        .map_err(|error| RuntimeError::StateRecordInvalid {
            reason: format!("{error}"),
        })?;
        self.store.append(&event, &record).map_err(RuntimeError::Store)?;
        self.next_sequence = sequence
            .checked_add(1)
            .ok_or(RuntimeError::SequenceOverflow)?;
        self.last_record = Some(record);
        self.state = committed_state;
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_store;
    use crate::in_process_host::{InProcessHost, NOP_PAYLOAD};
    use crate::state;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn must_ok<T, E: std::fmt::Display>(result: Result<T, E>, what: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{what} failed: {error}"),
        }
    }

    fn temp_path(tag: &str) -> PathBuf {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        std::env::temp_dir().join(format!("councilos-m1-runtime-{tag}-{pid}-{id}.jsonl"))
    }

    fn initial_state() -> CanonicalState {
        let mut state = CanonicalState::new();
        state.insert(
            "session".to_string(),
            CanonicalValue::Str("m1-unit".to_string()),
        );
        state.insert("nop_count".to_string(), CanonicalValue::Int(0));
        state.insert("last_sequence".to_string(), CanonicalValue::Int(0));
        state
    }

    fn new_runtime<H: HandlerHost>(tag: &str, host: H) -> (Runtime<H>, PathBuf) {
        let path = temp_path(tag);
        let store = must_ok(EventStore::create(&path, "m1-unit"), "create store");
        let runtime = must_ok(Runtime::new(PolicySet, initial_state(), host, store), "runtime");
        (runtime, path)
    }

    fn stored_pairs(path: &PathBuf) -> usize {
        must_ok(event_store::load(path), "load session").pairs.len()
    }

    fn denial() -> Instruction {
        Instruction {
            kind: NOP_KIND.to_string(),
            capability: "state.write".to_string(),
            args: CanonicalValue::Map(BTreeMap::new()),
        }
    }

    fn wrong_kind() -> Instruction {
        Instruction {
            kind: "write_state".to_string(),
            capability: NOP_CAPABILITY.to_string(),
            args: CanonicalValue::Map(BTreeMap::new()),
        }
    }

    struct ProtocolHost;
    impl HandlerHost for ProtocolHost {
        fn run(&mut self, _request: &HandlerRequest) -> Result<HandlerReply, HostError> {
            Err(HostError::Protocol {
                reason: "framed badly".to_string(),
            })
        }
    }

    struct CrashHost;
    impl HandlerHost for CrashHost {
        fn run(&mut self, _request: &HandlerRequest) -> Result<HandlerReply, HostError> {
            Err(HostError::Crashed {
                signal: Some(6),
                exit_code: None,
            })
        }
    }

    struct TimeoutHost;
    impl HandlerHost for TimeoutHost {
        fn run(&mut self, _request: &HandlerRequest) -> Result<HandlerReply, HostError> {
            Err(HostError::Timeout)
        }
    }

    struct IoHost;
    impl HandlerHost for IoHost {
        fn run(&mut self, _request: &HandlerRequest) -> Result<HandlerReply, HostError> {
            Err(HostError::Io {
                reason: "pipe closed".to_string(),
            })
        }
    }

    struct FlakyHost {
        failures_left: u32,
    }
    impl HandlerHost for FlakyHost {
        fn run(&mut self, _request: &HandlerRequest) -> Result<HandlerReply, HostError> {
            if self.failures_left > 0 {
                self.failures_left -= 1;
                return Err(HostError::Io {
                    reason: "transient spawn failure".to_string(),
                });
            }
            Ok(HandlerReply::Finished {
                payload: NOP_PAYLOAD.to_vec(),
            })
        }
    }

    struct SlowHost;
    impl HandlerHost for SlowHost {
        fn run(&mut self, _request: &HandlerRequest) -> Result<HandlerReply, HostError> {
            std::thread::sleep(std::time::Duration::from_millis(NOP_LEASE_MS + 100));
            Ok(HandlerReply::Finished {
                payload: NOP_PAYLOAD.to_vec(),
            })
        }
    }

    #[test]
    fn governed_nop_commits_event_state_and_pair() {
        let (mut runtime, path) = new_runtime("nop", InProcessHost);
        let event = must_ok(runtime.execute(Instruction::nop()), "execute nop");
        assert_eq!(event.sequence, 0);
        match &event.outcome {
            HandlerOutcome::Completed { evidence_ref } => {
                let expected = must_ok(
                    StateHash::compute(SCHEMA_VERSION, HashAlg::Blake3, NOP_PAYLOAD),
                    "recompute evidence",
                );
                assert_eq!(*evidence_ref, expected.digest);
            }
            _ => panic!("expected a Completed outcome"),
        }
        let canonical = must_ok(state::canonical(runtime.state()), "canonical state");
        assert_eq!(
            canonical.to_canonical_json(),
            "{\"last_sequence\":0,\"nop_count\":1,\"session\":\"m1-unit\"}"
        );
        let session = must_ok(event_store::load(&path), "load");
        assert_eq!(session.pairs.len(), 1);
        assert!(session.pairs[0].record.prev_hash.is_none());
    }

    #[test]
    fn gate_c_rejects_missing_capability_and_keeps_state() {
        let (mut runtime, path) = new_runtime("gate-cap", InProcessHost);
        let event = must_ok(runtime.execute(denial()), "execute denied");
        assert_eq!(event.sequence, 0);
        match &event.outcome {
            HandlerOutcome::Rejected { reason } => {
                assert!(reason.contains("capability gate"));
                assert!(reason.contains("state.write"));
            }
            _ => panic!("expected a Rejected outcome"),
        }
        let canonical = must_ok(state::canonical(runtime.state()), "canonical state");
        assert_eq!(
            canonical.to_canonical_json(),
            "{\"last_sequence\":0,\"nop_count\":0,\"session\":\"m1-unit\"}",
            "the gate rejection must not change state"
        );
        assert_eq!(stored_pairs(&path), 1, "the rejection is a recorded pair");
    }

    #[test]
    fn gate_c_rejects_wrong_kind_and_keeps_state() {
        let (mut runtime, path) = new_runtime("gate-kind", InProcessHost);
        let event = must_ok(runtime.execute(wrong_kind()), "execute wrong kind");
        match &event.outcome {
            HandlerOutcome::Rejected { reason } => assert!(reason.contains("write_state")),
            _ => panic!("expected a Rejected outcome"),
        }
        assert_eq!(stored_pairs(&path), 1);
    }

    #[test]
    fn rejection_reason_is_deterministic_across_events() {
        let (mut runtime, _path) = new_runtime("reason", InProcessHost);
        let first = must_ok(runtime.execute(denial()), "first denial");
        let second = must_ok(runtime.execute(denial()), "second denial");
        match (&first.outcome, &second.outcome) {
            (HandlerOutcome::Rejected { reason: one }, HandlerOutcome::Rejected { reason: two }) => {
                assert_eq!(one, two);
            }
            _ => panic!("both events must be rejections"),
        }
        assert_eq!(second.sequence, 1);
    }

    #[test]
    fn every_outcome_consumes_a_dense_sequence() {
        let (mut runtime, path) = new_runtime("dense", InProcessHost);
        let first = must_ok(runtime.execute(denial()), "rejected 0");
        assert_eq!(first.sequence, 0);
        let second = must_ok(runtime.execute(Instruction::nop()), "completed 1");
        assert_eq!(second.sequence, 1);
        let third = must_ok(runtime.execute(denial()), "rejected 2");
        assert_eq!(third.sequence, 2);
        assert_eq!(runtime.next_sequence, 3);
        assert_eq!(stored_pairs(&path), 3);
    }

    #[test]
    fn host_crash_error_records_crashed_with_signal() {
        let (mut runtime, path) = new_runtime("crash", CrashHost);
        let event = must_ok(runtime.execute(Instruction::nop()), "execute crash");
        match &event.outcome {
            HandlerOutcome::Crashed { signal, exit_code } => {
                assert_eq!(*signal, Some(6));
                assert_eq!(*exit_code, None);
            }
            _ => panic!("expected a Crashed outcome"),
        }
        let canonical = must_ok(state::canonical(runtime.state()), "canonical state");
        assert_eq!(
            canonical.to_canonical_json(),
            "{\"last_sequence\":0,\"nop_count\":0,\"session\":\"m1-unit\"}",
            "a crash must leave state unchanged"
        );
        assert_eq!(stored_pairs(&path), 1, "a crash is a recorded event");
    }

    #[test]
    fn protocol_error_records_crashed_without_signal() {
        let (mut runtime, path) = new_runtime("protocol", ProtocolHost);
        let event = must_ok(runtime.execute(Instruction::nop()), "execute protocol");
        match &event.outcome {
            HandlerOutcome::Crashed { signal, exit_code } => {
                assert_eq!(*signal, None);
                assert_eq!(*exit_code, None);
            }
            _ => panic!("expected a Crashed outcome"),
        }
        assert_eq!(stored_pairs(&path), 1);
    }

    #[test]
    fn host_timeout_error_records_timed_out() {
        let (mut runtime, path) = new_runtime("timeout", TimeoutHost);
        let event = must_ok(runtime.execute(Instruction::nop()), "execute timeout");
        match &event.outcome {
            HandlerOutcome::TimedOut => {}
            _ => panic!("expected a TimedOut outcome"),
        }
        assert_eq!(stored_pairs(&path), 1);
    }

    #[test]
    fn spawn_failure_surfaces_error_without_event_or_sequence() {
        let (mut runtime, path) = new_runtime("spawn-fail", IoHost);
        let before = must_ok(std::fs::read_to_string(&path), "read before");
        match runtime.execute(Instruction::nop()) {
            Err(RuntimeError::SpawnFailed { reason }) => {
                assert!(reason.contains("pipe closed"));
            }
            Err(other) => panic!("expected SpawnFailed, got {other}"),
            Ok(_) => panic!("a spawn failure must not produce an event"),
        }
        let after = must_ok(std::fs::read_to_string(&path), "read after");
        assert_eq!(before, after, "no line may be written on a spawn failure");
        assert_eq!(stored_pairs(&path), 0);
    }

    #[test]
    fn spawn_failure_allows_clean_reentry() {
        let (mut runtime, path) = new_runtime(
            "reentry",
            FlakyHost {
                failures_left: 1,
            },
        );
        match runtime.execute(Instruction::nop()) {
            Err(RuntimeError::SpawnFailed { reason }) => {
                assert!(reason.contains("transient"));
            }
            Ok(_) => panic!("the first call must fail"),
            Err(_) => panic!("the first call must be SpawnFailed"),
        }
        let event = must_ok(runtime.execute(Instruction::nop()), "clean re-entry");
        assert_eq!(event.sequence, 0, "a spawn failure consumes no sequence");
        assert_eq!(stored_pairs(&path), 1);
    }

    #[test]
    fn expired_lease_maps_completed_to_timed_out_without_commit() {
        let (mut runtime, path) = new_runtime("lease", SlowHost);
        let event = must_ok(runtime.execute(Instruction::nop()), "execute slow");
        match &event.outcome {
            HandlerOutcome::TimedOut => {}
            _ => panic!("expected a TimedOut outcome after an expired lease"),
        }
        let canonical = must_ok(state::canonical(runtime.state()), "canonical state");
        assert_eq!(
            canonical.to_canonical_json(),
            "{\"last_sequence\":0,\"nop_count\":0,\"session\":\"m1-unit\"}",
            "an expired lease must not commit execution effects"
        );
        assert_eq!(stored_pairs(&path), 1);
    }

    #[test]
    fn nop_count_wrong_type_is_state_build_invalid() {
        let path = temp_path("bad-count");
        let store = must_ok(EventStore::create(&path, "m1-unit"), "create store");
        let mut poisoned = initial_state();
        poisoned.insert(
            "nop_count".to_string(),
            CanonicalValue::Str("many".to_string()),
        );
        let mut runtime =
            must_ok(Runtime::new(PolicySet, poisoned, InProcessHost, store), "runtime");
        match runtime.execute(Instruction::nop()) {
            Err(RuntimeError::StateBuildInvalid { reason }) => {
                assert!(reason.contains("nop_count"));
            }
            Ok(_) => panic!("a poisoned state must not commit"),
            Err(_) => panic!("expected StateBuildInvalid"),
        }
        assert_eq!(stored_pairs(&path), 0);
    }

    #[test]
    fn nop_count_overflow_is_state_build_invalid() {
        let path = temp_path("count-overflow");
        let store = must_ok(EventStore::create(&path, "m1-unit"), "create store");
        let mut poisoned = initial_state();
        poisoned.insert("nop_count".to_string(), CanonicalValue::Int(i64::MAX));
        let mut runtime =
            must_ok(Runtime::new(PolicySet, poisoned, InProcessHost, store), "runtime");
        match runtime.execute(Instruction::nop()) {
            Err(RuntimeError::StateBuildInvalid { reason }) => {
                assert!(reason.contains("overflowed"));
            }
            Ok(_) => panic!("an overflowing counter must not commit"),
            Err(_) => panic!("expected StateBuildInvalid"),
        }
    }

    #[test]
    fn sequence_overflow_surfaces_error() {
        let (mut runtime, path) = new_runtime("seq-overflow", InProcessHost);
        runtime.next_sequence = u64::MAX;
        match runtime.execute(Instruction::nop()) {
            Err(RuntimeError::SequenceOverflow) => {}
            Ok(_) => panic!("a sequence overflow must abort the call"),
            Err(_) => panic!("expected SequenceOverflow"),
        }
        assert_eq!(stored_pairs(&path), 0);
    }

    #[test]
    fn policy_set_hash_matches_fixed_policy() {
        let (mut runtime, _path) = new_runtime("policy-hash", InProcessHost);
        let event = must_ok(runtime.execute(Instruction::nop()), "execute");
        let expected = must_ok(PolicySet.hash(HashAlg::Blake3), "policy hash");
        assert_eq!(event.policy_set_hash, expected);
    }
}
