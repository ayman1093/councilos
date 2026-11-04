//! Deterministic replay: fold a session log back into its state hashes.
//!
//! Traceability: M1.md §2 ("Load + replay: rebuild state from the log,
//! verify final hash") and §3 Gate A; `event_store.rs:29-31` (the header's
//! session name is the identity replay rebuilds states with), `42-45`
//! (whether the session's policy hash is the *right* policy is decided
//! here, against the compiled policy set), `131-136` (`HashMismatch` is
//! reserved for replay and fired only here).
//!
//! # What this module is
//!
//! [`event_store::load`] verifies structure — pairs, density, chain,
//! intra-session policy. This module verifies *content*: it folds every
//! recorded event back into a state, re-derives each [`StateRecord`] hash
//! through the exact same construction the runtime used, and refuses the
//! session at the first byte of divergence. The fold is a consumer of the
//! public interface only ([`load`], [`PolicySet`], [`StateRecord`],
//! `state::canonical`): the store is never touched, exactly as ruled for
//! this package.
//!
//! # The fold (a mirror of the frozen transition rules)
//!
//! `runtime.rs:200-276` is frozen, so the fold is written independently
//! here, mirroring it line for line: `Completed` advances `nop_count` (a
//! checked `+ 1` over the previous `Int`, or `0`) and sets
//! `last_sequence` to the event's sequence as `i64`; `Rejected`, `Crashed`
//! and `TimedOut` commit the state unchanged, so the fold holds it as is.
//! The fold works on its own self-built state — its keys are
//! `session`/`nop_count`/`last_sequence` with `Int` values only — so the
//! defensive arms below are unreachable in practice; they are still
//! written in the result vocabulary of the runtime and never swallowed.
//!
//! # Genesis
//!
//! There is no initial-state parameter. The genesis state is derived from
//! the header's session name (`event_store.rs:29-31`): the standard M1
//! template `{session: <header name>, nop_count: 0, last_sequence: 0}` — the
//! same shape a live runtime starts from. A wrong header name
//! therefore surfaces as a hash mismatch at the first pair, never as a
//! silent rename.
//!
//! # Policy
//!
//! [`load`] guarantees all events of one session carry the same
//! `policy_set_hash`. The fold compares that digest against the compiled
//! [`PolicySet`]'s Blake3 digest — the accumulated-set tooth (D17,
//! `event_store.rs:42-45`): a session recorded under any other policy is
//! refused with [`ReplayError::PolicyMismatch`] before its first fold.
//!
//! # Time
//!
//! `recorded_at_unix_ms` is excluded from every hash preimage
//! (`event.rs:12-15`), so the fold needs no clock: replaying the same file
//! in two processes produces the same bytes by construction — Gate A's
//! crossing leg.

use std::path::Path;

use crate::event::HandlerOutcome;
use crate::event_store::{load, ReplayError, StoreError};
use crate::policy::PolicySet;
use crate::state::{CanonicalState, CanonicalValue, HashAlg, StateRecord, StateHash};

/// The verified result of replaying a session log.
#[derive(Debug)]
pub struct Replayed {
    /// The final folded state — byte-equal to the live runtime's committed
    /// state when the session was honestly recorded.
    pub final_state: CanonicalState,
    /// Hash of the final folded state. For a non-empty session this is the
    /// last record's `state_hash`, re-derived and verified pair by pair; for
    /// a session with no pairs it is the genesis state's own hash.
    pub final_state_hash: StateHash,
    /// How many event/record pairs the fold verified before returning.
    pub verified_pairs: usize,
}

/// Failures of [`replay_session`].
///
/// Three families, as ruled for this package: the store's own verdict
/// ([`Store`]), the replay teeth ([`Replay`] — `HashMismatch` and the
/// accumulated-set `PolicyMismatch`, both fired by the fold), and the
/// `RuntimeError` vocabulary for failures that are theoretical only at
/// replay (the state is self-built, so hashing and record construction
/// cannot realistically fail — but the result is handled, never
/// swallowed). The third family carries the four arms the fold can reach:
/// `PolicyHashUnavailable`, `StateRecordInvalid`, `StateBuildInvalid` and
/// `SequenceOverflow` (`runtime.rs:64-94`); `SpawnFailed` and
/// `EvidenceHashUnavailable` cannot occur — replay spawns nothing and
/// hashes no evidence.
#[derive(Debug)]
pub enum ReplaySessionError {
    /// The session log could not be read or failed structural verification
    /// in [`load`].
    Store(StoreError),
    /// The fold refused the session: a replayed state hash or the compiled
    /// policy set diverged from what the log records.
    Replay(ReplayError),
    /// The compiled policy set could not be hashed.
    PolicyHashUnavailable {
        /// Rendered underlying cause.
        reason: String,
    },
    /// A state record could not be re-derived from the folded state.
    StateRecordInvalid {
        /// Rendered underlying cause.
        reason: String,
    },
    /// The folded state could not be advanced. Defensive arm, unreachable
    /// while the fold builds its own state from `Int`-only values — kept in
    /// the runtime's vocabulary so the mirror stays honest.
    StateBuildInvalid {
        /// Rendered underlying cause.
        reason: String,
    },
    /// The event sequence does not fit `i64` for `last_sequence`.
    SequenceOverflow,
}

impl std::fmt::Display for ReplaySessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplaySessionError::Store(error) => write!(f, "session store failure: {error}"),
            ReplaySessionError::Replay(error) => write!(f, "session replay failure: {error}"),
            ReplaySessionError::PolicyHashUnavailable { reason } => {
                write!(f, "policy set hash unavailable: {reason}")
            }
            ReplaySessionError::StateRecordInvalid { reason } => {
                write!(f, "state record invalid: {reason}")
            }
            ReplaySessionError::StateBuildInvalid { reason } => {
                write!(f, "state build invalid: {reason}")
            }
            ReplaySessionError::SequenceOverflow => write!(f, "sequence number overflowed"),
        }
    }
}

impl std::error::Error for ReplaySessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ReplaySessionError::Store(error) => Some(error),
            ReplaySessionError::Replay(error) => Some(error),
            _ => None,
        }
    }
}

/// Replay a session log and verify every state hash it commits to.
///
/// The genesis state is derived from the file's header name; the fold
/// mirrors the runtime's frozen transition rules; each re-derived record
/// hash must equal the recorded one or the session is refused with
/// [`ReplayError::HashMismatch`]. The session's `policy_set_hash` must
/// equal the Blake3 digest of `policy` ([`PolicySet::hash`]) or it is
/// refused with [`ReplayError::PolicyMismatch`] before the first fold.
///
/// Passing `PolicySet` by value mirrors `Runtime::new`
/// (`runtime.rs:144-149`): the policy set is a unit `Copy` struct.
pub fn replay_session(
    path: impl AsRef<Path>,
    policy: PolicySet,
) -> Result<Replayed, ReplaySessionError> {
    let session = load(path).map_err(ReplaySessionError::Store)?;
    let expected_policy = policy.hash(HashAlg::Blake3).map_err(|error| {
        ReplaySessionError::PolicyHashUnavailable {
            reason: format!("{error}"),
        }
    })?;

    let mut state = genesis_state(&session.name);
    // The genesis baseline: the hash an empty session returns, computed
    // through the same canonical-JSON construction every other state hash
    // uses. The placeholder sequence never enters the state hash; only the
    // record's own (unused) canonical form would carry it.
    let genesis_hash = StateRecord::new(0, &state, None, HashAlg::Blake3)
        .map_err(|error| ReplaySessionError::StateRecordInvalid {
            reason: format!("{error}"),
        })?
        .state_hash;

    let mut prev: Option<StateRecord> = None;
    let mut verified_pairs: usize = 0;

    for pair in &session.pairs {
        // The accumulated-set tooth: every event carries the session's one
        // policy hash; it must be the compiled set's digest.
        if pair.event.policy_set_hash != expected_policy {
            return Err(ReplaySessionError::Replay(ReplayError::PolicyMismatch {
                sequence: pair.event.sequence,
            }));
        }

        // The fold — a line-for-line mirror of the runtime's transition
        // rules (runtime.rs:200-276). Rejected, Crashed and TimedOut
        // commit the state unchanged, so only Completed advances it.
        match &pair.event.outcome {
            HandlerOutcome::Completed { .. } => {
                let previous = match state.get("nop_count") {
                    None => 0,
                    Some(CanonicalValue::Int(value)) => *value,
                    Some(_) => {
                        return Err(ReplaySessionError::StateBuildInvalid {
                            reason: "existing `nop_count` is not an integer".to_string(),
                        });
                    }
                };
                let next_count = previous.checked_add(1).ok_or_else(|| {
                    ReplaySessionError::StateBuildInvalid {
                        reason: "`nop_count` overflowed i64".to_string(),
                    }
                })?;
                let sequence_i64 = i64::try_from(pair.event.sequence)
                    .map_err(|_| ReplaySessionError::SequenceOverflow)?;
                state.insert("nop_count".to_string(), CanonicalValue::Int(next_count));
                state.insert(
                    "last_sequence".to_string(),
                    CanonicalValue::Int(sequence_i64),
                );
            }
            HandlerOutcome::Rejected { .. }
            | HandlerOutcome::Crashed { .. }
            | HandlerOutcome::TimedOut => {
                // The unchanged state is committed (runtime.rs:186, 203,
                // 215, 227) — the fold holds `state` exactly as it is.
            }
        }

        // Re-derive the record through the runtime's own construction and
        // compare. The store has already chained `prev_hash` at load; the
        // fold's job is the state hash itself.
        let rebuilt = StateRecord::new(
            pair.event.sequence,
            &state,
            prev.as_ref(),
            HashAlg::Blake3,
        )
        .map_err(|error| ReplaySessionError::StateRecordInvalid {
            reason: format!("{error}"),
        })?;
        if rebuilt.state_hash != pair.record.state_hash {
            return Err(ReplaySessionError::Replay(ReplayError::HashMismatch {
                sequence: pair.event.sequence,
            }));
        }
        prev = Some(rebuilt);
        verified_pairs += 1;
    }

    let final_state_hash = match &prev {
        Some(record) => record.state_hash,
        None => genesis_hash,
    };

    Ok(Replayed {
        final_state: state,
        final_state_hash,
        verified_pairs,
    })
}

/// The standard M1 genesis state for `name`.
///
/// `{session: <name>, nop_count: 0, last_sequence: 0}` — the same template
/// a live runtime starts from (`tests/m1_policy.rs:43-52`). The header's
/// session name is the identity replay rebuilds states with
/// (`event_store.rs:29-31`); a session whose live states were keyed by any
/// other name fails the fold's first comparison.
fn genesis_state(name: &str) -> CanonicalState {
    let mut state = CanonicalState::new();
    state.insert(
        "session".to_string(),
        CanonicalValue::Str(name.to_string()),
    );
    state.insert("nop_count".to_string(), CanonicalValue::Int(0));
    state.insert("last_sequence".to_string(), CanonicalValue::Int(0));
    state
}

// unverified — needs CI
#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_store::EventStore;
    use crate::in_process_host::InProcessHost;
    use crate::instruction::Instruction;
    use crate::runtime::Runtime;
    use crate::state::canonical;
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
        std::env::temp_dir().join(format!("councilos-m1-replay-{tag}-{pid}-{id}.jsonl"))
    }

    fn live_initial_state(name: &str) -> CanonicalState {
        let mut state = CanonicalState::new();
        state.insert(
            "session".to_string(),
            CanonicalValue::Str(name.to_string()),
        );
        state.insert("nop_count".to_string(), CanonicalValue::Int(0));
        state.insert("last_sequence".to_string(), CanonicalValue::Int(0));
        state
    }

    #[test]
    fn genesis_is_derived_from_the_header_name() {
        let path = temp_path("empty-session");
        let store = must_ok(EventStore::create(&path, "m1-empty"), "create store");
        drop(store);

        let replayed = must_ok(replay_session(&path, PolicySet), "replay");
        assert_eq!(
            replayed.final_state,
            live_initial_state("m1-empty"),
            "an empty session replays to the genesis derived from the header"
        );
        assert_eq!(replayed.verified_pairs, 0);
        let expected = must_ok(
            must_ok(canonical(&replayed.final_state), "canonical").hash(HashAlg::Blake3),
            "genesis hash",
        );
        assert_eq!(replayed.final_state_hash, expected);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wrong_header_name_surfaces_as_hash_mismatch_at_sequence_zero() {
        let path = temp_path("wrong-name");
        // The header name and the state's `session` key are independent in
        // M1 (runtime.rs:44-46): a runtime keyed by one name over a store
        // headed by another writes states the fold cannot rebuild from the
        // header — the promised wrong-name mechanism (event_store.rs:29-31).
        let store = must_ok(EventStore::create(&path, "header-name"), "create store");
        let mut runtime = must_ok(
            Runtime::new(
                PolicySet,
                live_initial_state("state-name"),
                InProcessHost,
                store,
            ),
            "runtime",
        );
        must_ok(runtime.execute(Instruction::nop()), "execute nop");

        match replay_session(&path, PolicySet) {
            Err(ReplaySessionError::Replay(ReplayError::HashMismatch { sequence })) => {
                assert_eq!(sequence, 0);
            }
            other => panic!("expected a hash mismatch at sequence 0, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_surfaces_as_store_io() {
        let path = temp_path("missing");
        match replay_session(&path, PolicySet) {
            Err(ReplaySessionError::Store(StoreError::Io(_))) => {}
            other => panic!("expected a store i/o failure, got {other:?}"),
        }
    }
}
