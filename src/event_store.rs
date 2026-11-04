//! Append-only session log (D17): one JSONL file per session.
//!
//! # What this module is
//!
//! The store is the wire half of evidence. It frames an [`Event`] and the
//! [`StateRecord`] that commits to the state after it into a single append-only
//! file, and refuses to read back anything that does not obey the session
//! rules. It does not interpret outcomes, apply instructions, or decide policy
//! — that is the runtime's job (P1.3+).
//!
//! # File layout
//!
//! ```text
//! {"type":"session","session":"<name>"}
//! {"type":"event",...}
//! {"type":"state_record",...}
//! {"type":"event",...}
//! {"type":"state_record",...}
//! ```
//!
//! * The first line is the session header, written by [`EventStore::create`].
//!   It is deliberately minimal; a future schema may add fields to it without
//!   touching the hash layer — the whole envelope is wire-only (بند 17:
//!   wire-vs-hash separation). Nothing here enters any hash preimage.
//! * Every event line is followed by exactly one `state_record` line that
//!   commits to the state produced by that event. The hashable truth lives in
//!   the `Event`/`StateRecord` values themselves, exactly as M0 defines them.
//!
//! The header's session name is the identity replay uses to rebuild states
//! (the state's canonical form carries it); a wrong name surfaces as a hash
//! mismatch at replay (P1.5), not here.
//!
//! # Integrity rules (checked at append and re-checked at load)
//!
//! 1. Event sequences are dense and start at 0 ([`ReplayError::SequenceGap`]).
//! 2. `record.sequence == event.sequence` for every pair
//!    ([`ReplayError::ChainMismatch`]).
//! 3. `record.prev_hash` equals the previous record's state hash; the first
//!    record carries `None` ([`ReplayError::ChainMismatch`]). The chain links
//!    states: genesis has no predecessor, and every later record commits to
//!    the state it builds on.
//! 4. All events of one session carry the same `policy_set_hash`
//!    ([`ReplayError::PolicyMismatch`]). This is an intra-session consistency
//!    check only: whether that hash is the *right* policy is decided at replay
//!    time against the compiled policy set (P1.5), not here.
//!
//! # Torn tails
//!
//! A session file that does not end with `\n`, or whose last complete pair is
//! an event without its record, is reported as [`ReplayError::TornTail`] and
//! is never repaired in place. An interrupted write must be visible as damage,
//! not silently smoothed over (M1.md: errors are surfaced, never swallowed).
//!
//! # Died ≠ never started
//!
//! A handler that died is an event (`Crashed`) and is in this log. A handler
//! that never started is a runtime error (`RuntimeError::SpawnFailed`) and
//! never reaches the store: the log records what happened, not what failed to
//! begin. (Runtime side: P1.3/P1.4. This module only documents the line.)
//!
//! # Evidence (D18)
//!
//! The evidence blob is **not** stored in M1. Only the digest inside the event
//! (`evidence_ref`) is kept. الوعد في M1 = replay يعيد إنتاج الهاشات من السجل،
//! لا recompute evidence من الحمولة.
//!
//! # Crypto-shredding (بند 18)
//!
//! Lines are self-contained records. A future per-entity encryption layer can
//! wrap each line without reshaping the log format; nothing in M1 assumes
//! plaintext beyond the envelope.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::event::Event;
use crate::state::{StateHash, StateRecord};

/// A verified session as read back by [`load`].
#[derive(Debug)]
pub struct Session {
    /// Session name from the header line.
    pub name: String,
    /// Verified event/record pairs, in dense sequence order (0-based).
    pub pairs: Vec<StoredPair>,
}

/// One verified event and the state record that follows it.
#[derive(Debug)]
pub struct StoredPair {
    /// The event half of the committed pair.
    pub event: Event,
    /// The state record half of the committed pair.
    pub record: StateRecord,
}

/// Integrity failures of a session log.
///
/// Produced by the store's write path and by [`load`]. Replay (P1.5) uses the
/// same vocabulary and adds the checks that need replayed states
/// ([`ReplayError::HashMismatch`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayError {
    /// A complete line that is not valid JSON for any known line type.
    MalformedLine {
        /// 1-based line number.
        line: u64,
    },
    /// A line that was never completed: the file ends mid-line, or an event
    /// line is missing the record line it promises.
    TornTail {
        /// 1-based line number of the torn (or expected-missing) line.
        line: u64,
    },
    /// Event sequences must be dense and start at 0.
    SequenceGap {
        /// The sequence number the store expected next.
        expected: u64,
        /// The sequence number actually found on disk.
        found: u64,
    },
    /// Pair or chain violation: `record.sequence != event.sequence`, or
    /// `record.prev_hash` does not match the preceding record's state hash.
    ChainMismatch {
        /// The event sequence whose record failed chain verification.
        sequence: u64,
    },
    /// Replayed state does not hash to the recorded state hash. Reserved for
    /// replay (P1.5); the store itself never produces it.
    HashMismatch {
        /// The event sequence whose replayed state hash did not match (fired by replay, never by the store).
        sequence: u64,
    },
    /// An event's `policy_set_hash` diverges from the session's. Replay (P1.5)
    /// also uses this against the compiled policy set.
    PolicyMismatch {
        /// The event sequence whose policy set hash diverged from the session's.
        sequence: u64,
    },
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplayError::MalformedLine { line } => {
                write!(f, "line {line}: not a valid session-log line")
            }
            ReplayError::TornTail { line } => {
                write!(f, "line {line}: torn tail (write interrupted)")
            }
            ReplayError::SequenceGap { expected, found } => {
                write!(f, "sequence gap: expected {expected}, found {found}")
            }
            ReplayError::ChainMismatch { sequence } => {
                write!(f, "chain mismatch at sequence {sequence}")
            }
            ReplayError::HashMismatch { sequence } => {
                write!(f, "hash mismatch at sequence {sequence}")
            }
            ReplayError::PolicyMismatch { sequence } => {
                write!(f, "policy mismatch at sequence {sequence}")
            }
        }
    }
}

impl std::error::Error for ReplayError {}

/// Failures of store operations.
///
/// I/O and integrity are kept apart on purpose: an unreadable file can be
/// retried, a corrupt log is evidence damage and is never repaired in place.
#[derive(Debug)]
pub enum StoreError {
    /// The bytes could not be read or written.
    Io(std::io::Error),
    /// The log itself violates the session rules.
    Integrity(ReplayError),
}

impl From<std::io::Error> for StoreError {
    fn from(error: std::io::Error) -> Self {
        StoreError::Io(error)
    }
}

impl From<ReplayError> for StoreError {
    fn from(error: ReplayError) -> Self {
        StoreError::Integrity(error)
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(error) => write!(f, "i/o error: {error}"),
            StoreError::Integrity(error) => write!(f, "session integrity: {error}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StoreError::Io(error) => Some(error),
            StoreError::Integrity(_) => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum LogLine {
    Session(SessionHeader),
    Event(Event),
    StateRecord(StateRecord),
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionHeader {
    session: String,
}

/// The append handle of a live session.
///
/// Keeps the file open and enforces the session rules before every write; a
/// rejected append leaves the file byte-identical.
#[derive(Debug)]
pub struct EventStore {
    file: File,
    next_sequence: u64,
    last_state_hash: Option<StateHash>,
    policy_set_hash: Option<crate::Hash32>,
}

impl EventStore {
    /// Create a new session log and write its header.
    ///
    /// Refuses to overwrite an existing path: a session file is evidence,
    /// never a scratch buffer. Resuming an old session is not part of M1.
    pub fn create(path: impl AsRef<Path>, session: &str) -> Result<EventStore, StoreError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        let header = SessionHeader {
            session: session.to_owned(),
        };
        file.write_all(line_json(&LogLine::Session(header))?.as_bytes())?;
        file.write_all(b"\n")?;
        file.flush()?;
        Ok(EventStore {
            file,
            next_sequence: 0,
            last_state_hash: None,
            policy_set_hash: None,
        })
    }

    /// Append one event and its state record.
    ///
    /// All rules are checked before a byte is written: a rejected append
    /// leaves the file untouched. The pair is written with a single
    /// `write_all`, so a crash can tear the tail but cannot interleave the
    /// two lines.
    pub fn append(&mut self, event: &Event, record: &StateRecord) -> Result<(), StoreError> {
        let expected = self.next_sequence;
        if event.sequence != expected {
            return Err(ReplayError::SequenceGap {
                expected,
                found: event.sequence,
            }
            .into());
        }
        if record.sequence != event.sequence {
            return Err(ReplayError::ChainMismatch {
                sequence: event.sequence,
            }
            .into());
        }
        if record.prev_hash != self.last_state_hash {
            return Err(ReplayError::ChainMismatch {
                sequence: event.sequence,
            }
            .into());
        }
        if let Some(policy) = self.policy_set_hash {
            if event.policy_set_hash != policy {
                return Err(ReplayError::PolicyMismatch {
                    sequence: event.sequence,
                }
                .into());
            }
        }

        let mut pair = line_json(&LogLine::Event(event.clone()))?;
        pair.push('\n');
        pair.push_str(&line_json(&LogLine::StateRecord(record.clone()))?);
        pair.push('\n');
        self.file.write_all(pair.as_bytes())?;
        self.file.flush()?;

        if self.policy_set_hash.is_none() {
            self.policy_set_hash = Some(event.policy_set_hash);
        }
        self.next_sequence += 1;
        self.last_state_hash = Some(record.state_hash);
        Ok(())
    }
}

/// Read a session log and verify it end to end.
///
/// Verification is structural (pairs, density, chain, policy). Hash
/// recomputation against replayed states is replay's job (P1.5).
pub fn load(path: impl AsRef<Path>) -> Result<Session, StoreError> {
    let bytes = std::fs::read(path)?;
    if bytes.is_empty() {
        // A session file that never got its header was interrupted before the
        // first byte of truth: treat it as a torn first line.
        return Err(ReplayError::TornTail { line: 1 }.into());
    }

    let torn = !bytes.ends_with(b"\n");
    let complete: &[u8] = if torn {
        match bytes.iter().rposition(|byte| *byte == b'\n') {
            Some(index) => &bytes[..=index],
            None => &[],
        }
    } else {
        &bytes
    };

    let text = std::str::from_utf8(complete).map_err(|error| {
        let line = complete[..error.valid_up_to()]
            .iter()
            .filter(|byte| **byte == b'\n')
            .count() as u64
            + 1;
        ReplayError::MalformedLine { line }
    })?;

    let mut header: Option<SessionHeader> = None;
    let mut pending_event: Option<Event> = None;
    let mut last_state_hash: Option<StateHash> = None;
    let mut policy_set_hash: Option<crate::Hash32> = None;
    let mut pairs: Vec<StoredPair> = Vec::new();
    let mut line_count: u64 = 0;

    for (index, raw) in text.lines().enumerate() {
        let line = index as u64 + 1;
        line_count = line;
        let parsed: LogLine =
            serde_json::from_str(raw).map_err(|_| ReplayError::MalformedLine { line })?;

        match parsed {
            LogLine::Session(session_header) => {
                if header.is_some() || line != 1 {
                    // The header opens the file and appears exactly once.
                    return Err(ReplayError::MalformedLine { line }.into());
                }
                header = Some(session_header);
            }
            LogLine::Event(event) => {
                if header.is_none() {
                    return Err(ReplayError::MalformedLine { line }.into());
                }
                if pending_event.is_some() {
                    // Two events in a row: the first one lost its record.
                    return Err(ReplayError::ChainMismatch {
                        sequence: pairs.len() as u64,
                    }
                    .into());
                }
                let expected = pairs.len() as u64;
                if event.sequence != expected {
                    return Err(ReplayError::SequenceGap {
                        expected,
                        found: event.sequence,
                    }
                    .into());
                }
                match policy_set_hash {
                    Some(policy) if event.policy_set_hash != policy => {
                        return Err(ReplayError::PolicyMismatch {
                            sequence: event.sequence,
                        }
                        .into());
                    }
                    None => policy_set_hash = Some(event.policy_set_hash),
                    Some(_) => {}
                }
                pending_event = Some(event);
            }
            LogLine::StateRecord(record) => {
                if header.is_none() {
                    return Err(ReplayError::MalformedLine { line }.into());
                }
                let event = match pending_event.take() {
                    Some(event) => event,
                    None => {
                        // A record without its event: the pair structure is broken.
                        return Err(ReplayError::ChainMismatch {
                            sequence: record.sequence,
                        }
                        .into());
                    }
                };
                if record.sequence != event.sequence {
                    return Err(ReplayError::ChainMismatch {
                        sequence: event.sequence,
                    }
                    .into());
                }
                if record.prev_hash != last_state_hash {
                    return Err(ReplayError::ChainMismatch {
                        sequence: event.sequence,
                    }
                    .into());
                }
                last_state_hash = Some(record.state_hash);
                pairs.push(StoredPair { event, record });
            }
        }
    }

    let header = match header {
        Some(header) => header,
        None => {
            // No complete line carried a header (empty complete prefix of a
            // torn file).
            return Err(ReplayError::TornTail { line: 1 }.into());
        }
    };

    if pending_event.is_some() || torn {
        // The last event never got its record, or the file ends mid-line.
        return Err(ReplayError::TornTail {
            line: line_count + 1,
        }
        .into());
    }

    Ok(Session {
        name: header.session,
        pairs,
    })
}

fn line_json(line: &LogLine) -> Result<String, StoreError> {
    serde_json::to_string(line).map_err(|error| {
        StoreError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    })
}

// unverified — needs CI
#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, HandlerOutcome};
    use crate::instruction::Instruction;
    use crate::state::{CanonicalState, HashAlg, StateRecord};
    use crate::Hash32;
    use std::collections::BTreeMap;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    // The store never interprets the *content* of a state — it only chains the
    // state hashes that StateRecord::new derives. Empty maps are therefore
    // legitimate here; the frozen M0 state content lives in m0_golden.rs only.
    const POLICY_A: Hash32 = [0x33; 32];
    const POLICY_B: Hash32 = [0x44; 32];
    const EVIDENCE: Hash32 = [0x11; 32];

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
        std::env::temp_dir().join(format!("councilos-m1-event-store-{tag}-{pid}-{id}.jsonl"))
    }

    fn empty_state() -> CanonicalState {
        BTreeMap::new()
    }

    fn completed_event(sequence: u64, policy_set_hash: Hash32) -> Event {
        Event {
            sequence,
            recorded_at_unix_ms: 1_700_000_000_000 + sequence,
            instruction: Instruction::nop(),
            outcome: HandlerOutcome::Completed {
                evidence_ref: EVIDENCE,
            },
            policy_set_hash,
        }
    }

    fn record_at(sequence: u64, prev: Option<&StateRecord>) -> StateRecord {
        let state = empty_state();
        match StateRecord::new(sequence, &state, prev, HashAlg::Blake3) {
            Ok(record) => record,
            Err(_) => panic!("building an empty state record must not fail"),
        }
    }

    fn session_line() -> LogLine {
        LogLine::Session(SessionHeader {
            session: "m1-test".to_string(),
        })
    }

    fn log_text(lines: &[LogLine]) -> String {
        let mut text = String::new();
        for line in lines {
            text.push_str(&must_ok(line_json(line), "encode log line"));
            text.push('\n');
        }
        text
    }

    fn seed(path: &Path, lines: &[LogLine]) {
        must_ok(fs::write(path, log_text(lines)), "seed session file");
    }

    fn expect_integrity(path: &Path, what: &str) -> ReplayError {
        match load(path) {
            Err(StoreError::Integrity(replay)) => replay,
            Err(StoreError::Io(error)) => panic!("{what}: unexpected io error: {error}"),
            Ok(session) => panic!(
                "{what}: expected rejection, got {} committed pairs",
                session.pairs.len()
            ),
        }
    }

    #[test]
    fn session_roundtrips_with_header_and_dense_pairs() {
        let path = temp_path("roundtrip");
        let mut store = must_ok(EventStore::create(&path, "m1-test"), "create");
        let genesis = record_at(0, None);
        let second = record_at(1, Some(&genesis));
        must_ok(store.append(&completed_event(0, POLICY_A), &genesis), "append 0");
        must_ok(store.append(&completed_event(1, POLICY_A), &second), "append 1");
        drop(store);

        let text = must_ok(fs::read_to_string(&path), "read log");
        assert!(
            text.starts_with("{\"type\":\"session\",\"session\":\"m1-test\"}\n"),
            "the first line of the log must be the session header"
        );

        let session = must_ok(load(&path), "load");
        assert_eq!(session.name, "m1-test");
        assert_eq!(session.pairs.len(), 2);
        assert_eq!(session.pairs[0].event.sequence, 0);
        assert_eq!(session.pairs[1].event.sequence, 1);
        assert!(
            session.pairs[0].record.prev_hash.is_none(),
            "the genesis record must not carry a prev_hash"
        );
        match &session.pairs[1].record.prev_hash {
            Some(prev_hash) => assert!(
                prev_hash == &session.pairs[0].record.state_hash,
                "the second record must chain to the first record's state hash"
            ),
            None => panic!("the second record must chain to the first record's state hash"),
        }
        assert_eq!(session.pairs[0].event.policy_set_hash, POLICY_A);
        assert_eq!(session.pairs[1].event.policy_set_hash, POLICY_A);
    }

    #[test]
    fn torn_tail_is_rejected() {
        let path = temp_path("torn-tail");
        seed(
            &path,
            &[
                session_line(),
                LogLine::Event(completed_event(0, POLICY_A)),
                LogLine::StateRecord(record_at(0, None)),
            ],
        );
        let mut file = must_ok(OpenOptions::new().append(true).open(&path), "open for append");
        must_ok(file.write_all(b"{\"type\":\"event\""), "write torn tail");
        drop(file);

        match expect_integrity(&path, "torn tail") {
            ReplayError::TornTail { line } => assert_eq!(line, 4),
            other => panic!("expected TornTail, got {other}"),
        }
    }

    #[test]
    fn event_without_record_is_torn() {
        let path = temp_path("pending-event");
        seed(
            &path,
            &[
                session_line(),
                LogLine::Event(completed_event(0, POLICY_A)),
            ],
        );
        match expect_integrity(&path, "pending event") {
            ReplayError::TornTail { line } => assert_eq!(line, 3),
            other => panic!("expected TornTail, got {other}"),
        }
    }

    #[test]
    fn malformed_lines_are_rejected() {
        let invalid_json = temp_path("malformed-json");
        let mut text = log_text(&[session_line()]);
        text.push_str("not json\n");
        must_ok(fs::write(&invalid_json, text), "seed invalid json");
        match expect_integrity(&invalid_json, "invalid json") {
            ReplayError::MalformedLine { line } => assert_eq!(line, 2),
            other => panic!("expected MalformedLine, got {other}"),
        }

        let unknown_type = temp_path("malformed-type");
        let mut text = log_text(&[session_line()]);
        text.push_str("{\"type\":\"mystery\"}\n");
        must_ok(fs::write(&unknown_type, text), "seed unknown line type");
        match expect_integrity(&unknown_type, "unknown line type") {
            ReplayError::MalformedLine { line } => assert_eq!(line, 2),
            other => panic!("expected MalformedLine, got {other}"),
        }
    }

    #[test]
    fn first_line_must_be_the_session_header() {
        let path = temp_path("header-first");
        seed(
            &path,
            &[
                LogLine::Event(completed_event(0, POLICY_A)),
                LogLine::StateRecord(record_at(0, None)),
            ],
        );
        match expect_integrity(&path, "header first") {
            ReplayError::MalformedLine { line } => assert_eq!(line, 1),
            other => panic!("expected MalformedLine, got {other}"),
        }
    }

    #[test]
    fn duplicate_header_is_rejected() {
        let path = temp_path("duplicate-header");
        seed(&path, &[session_line(), session_line()]);
        match expect_integrity(&path, "duplicate header") {
            ReplayError::MalformedLine { line } => assert_eq!(line, 2),
            other => panic!("expected MalformedLine, got {other}"),
        }
    }

    #[test]
    fn dense_sequences_are_enforced_on_load() {
        let path = temp_path("sequence-gap");
        seed(
            &path,
            &[
                session_line(),
                LogLine::Event(completed_event(1, POLICY_A)),
                LogLine::StateRecord(record_at(1, None)),
            ],
        );
        match expect_integrity(&path, "sequence gap") {
            ReplayError::SequenceGap { expected, found } => {
                assert_eq!(expected, 0);
                assert_eq!(found, 1);
            }
            other => panic!("expected SequenceGap, got {other}"),
        }
    }

    #[test]
    fn broken_prev_hash_chain_is_rejected() {
        let path = temp_path("broken-chain");
        seed(
            &path,
            &[
                session_line(),
                LogLine::Event(completed_event(0, POLICY_A)),
                LogLine::StateRecord(record_at(0, None)),
                LogLine::Event(completed_event(1, POLICY_A)),
                LogLine::StateRecord(record_at(1, None)),
            ],
        );
        match expect_integrity(&path, "broken chain") {
            ReplayError::ChainMismatch { sequence } => assert_eq!(sequence, 1),
            other => panic!("expected ChainMismatch, got {other}"),
        }
    }

    #[test]
    fn policy_divergence_is_rejected() {
        let path = temp_path("policy-divergence");
        let genesis = record_at(0, None);
        let second = record_at(1, Some(&genesis));
        seed(
            &path,
            &[
                session_line(),
                LogLine::Event(completed_event(0, POLICY_A)),
                LogLine::StateRecord(genesis),
                LogLine::Event(completed_event(1, POLICY_B)),
                LogLine::StateRecord(second),
            ],
        );
        match expect_integrity(&path, "policy divergence") {
            ReplayError::PolicyMismatch { sequence } => assert_eq!(sequence, 1),
            other => panic!("expected PolicyMismatch, got {other}"),
        }
    }

    #[test]
    fn append_rejects_gap_and_leaves_file_untouched() {
        let path = temp_path("append-gap");
        let mut store = must_ok(EventStore::create(&path, "m1-test"), "create");
        must_ok(
            store.append(&completed_event(0, POLICY_A), &record_at(0, None)),
            "append genesis",
        );
        let before = must_ok(fs::read_to_string(&path), "read before");

        let chain_source = record_at(0, None);
        let gap_record = record_at(2, Some(&chain_source));
        match store.append(&completed_event(2, POLICY_A), &gap_record) {
            Err(StoreError::Integrity(ReplayError::SequenceGap { expected, found })) => {
                assert_eq!(expected, 1);
                assert_eq!(found, 2);
            }
            Err(other) => panic!("expected SequenceGap, got {other}"),
            Ok(()) => panic!("a gapped append must be rejected"),
        }

        let after = must_ok(fs::read_to_string(&path), "read after");
        assert_eq!(before, after, "a rejected append must not touch the log");

        let next = record_at(1, Some(&chain_source));
        must_ok(
            store.append(&completed_event(1, POLICY_A), &next),
            "append after rejection",
        );
        drop(store);

        let session = must_ok(load(&path), "load");
        assert_eq!(session.pairs.len(), 2);
    }

    #[test]
    fn append_rejects_broken_chain_and_wrong_pair_sequence() {
        let path = temp_path("append-chain");
        let mut store = must_ok(EventStore::create(&path, "m1-test"), "create");
        must_ok(
            store.append(&completed_event(0, POLICY_A), &record_at(0, None)),
            "append genesis",
        );

        match store.append(&completed_event(1, POLICY_A), &record_at(1, None)) {
            Err(StoreError::Integrity(ReplayError::ChainMismatch { sequence })) => {
                assert_eq!(sequence, 1);
            }
            Err(other) => panic!("expected ChainMismatch for a broken chain, got {other}"),
            Ok(()) => panic!("a broken chain must be rejected"),
        }

        let rebuild = record_at(0, None);
        let mismatched = record_at(0, Some(&rebuild));
        match store.append(&completed_event(1, POLICY_A), &mismatched) {
            Err(StoreError::Integrity(ReplayError::ChainMismatch { sequence })) => {
                assert_eq!(sequence, 1);
            }
            Err(other) => panic!("expected ChainMismatch for a pair sequence mismatch, got {other}"),
            Ok(()) => panic!("a pair sequence mismatch must be rejected"),
        }

        let proper = record_at(1, Some(&rebuild));
        must_ok(
            store.append(&completed_event(1, POLICY_A), &proper),
            "append after rejections",
        );
        drop(store);

        let session = must_ok(load(&path), "load");
        assert_eq!(session.pairs.len(), 2);
    }

    #[test]
    fn append_rejects_policy_change_within_a_session() {
        let path = temp_path("append-policy");
        let mut store = must_ok(EventStore::create(&path, "m1-test"), "create");
        must_ok(
            store.append(&completed_event(0, POLICY_A), &record_at(0, None)),
            "append genesis",
        );
        let rebuild = record_at(0, None);
        let chained = record_at(1, Some(&rebuild));
        match store.append(&completed_event(1, POLICY_B), &chained) {
            Err(StoreError::Integrity(ReplayError::PolicyMismatch { sequence })) => {
                assert_eq!(sequence, 1);
            }
            Err(other) => panic!("expected PolicyMismatch, got {other}"),
            Ok(()) => panic!("a policy change within a session must be rejected"),
        }
    }

    #[test]
    fn create_refuses_to_overwrite_an_existing_file() {
        let path = temp_path("create-twice");
        let first = must_ok(EventStore::create(&path, "m1-test"), "first create");
        drop(first);
        let before = must_ok(fs::read_to_string(&path), "read after first create");
        match EventStore::create(&path, "m1-test") {
            Err(StoreError::Io(error)) => {
                assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
            }
            Err(other) => panic!("expected an io error, got {other}"),
            Ok(_) => panic!("create must refuse to overwrite an existing session file"),
        }
        let after = must_ok(fs::read_to_string(&path), "read after refused create");
        assert_eq!(before, after, "a refused create must not touch the existing file");
    }
}
