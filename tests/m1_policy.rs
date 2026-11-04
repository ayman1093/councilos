//! P1.3 golden — the governed path frozen byte-exact from its first day.
//!
//! Extension under `M1.md:39` ("extending `tests/`, never modifying them"):
//! `tests/m0_golden.rs` is untouched (its fingerprint is re-verified with the
//! round). The state literals below have no anchor in `M1.md`; per the
//! reviewer's ruling they are frozen here from day one — any change to them
//! is an owner decision, not test drift.

use councilos_kernel::event::HandlerOutcome;
use councilos_kernel::event_store;
use councilos_kernel::in_process_host::{InProcessHost, NOP_PAYLOAD};
use councilos_kernel::instruction::{Instruction, NOP_KIND};
use councilos_kernel::policy::PolicySet;
use councilos_kernel::runtime::Runtime;
use councilos_kernel::state::{self, CanonicalState, CanonicalValue, HashAlg, StateHash};
use councilos_kernel::SCHEMA_VERSION;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const SESSION: &str = "m1-golden";
const POLICY_CANONICAL: &str =
    "{\"rules\":[{\"allow\":true,\"capability\":\"kernel.nop\",\"kind\":\"nop\"}]}";
const INITIAL_STATE_CANONICAL: &str =
    "{\"last_sequence\":0,\"nop_count\":0,\"session\":\"m1-golden\"}";
const FINAL_STATE_CANONICAL: &str =
    "{\"last_sequence\":0,\"nop_count\":1,\"session\":\"m1-golden\"}";

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
    std::env::temp_dir().join(format!("councilos-m1-policy-{tag}-{pid}-{id}.jsonl"))
}

fn initial_state() -> CanonicalState {
    let mut state = CanonicalState::new();
    state.insert(
        "session".to_string(),
        CanonicalValue::Str(SESSION.to_string()),
    );
    state.insert("nop_count".to_string(), CanonicalValue::Int(0));
    state.insert("last_sequence".to_string(), CanonicalValue::Int(0));
    state
}

fn state_json(runtime: &Runtime<InProcessHost>) -> String {
    let canonical = must_ok(state::canonical(runtime.state()), "canonical state");
    canonical.to_canonical_json()
}

#[test]
fn policy_canonical_is_frozen_byte_exact() {
    let canonical = must_ok(PolicySet.to_canonical(), "canonical policy");
    assert_eq!(canonical.to_canonical_json(), POLICY_CANONICAL);
}

#[test]
fn governed_nop_path_is_frozen() {
    let path = temp_path("governed");
    let store = must_ok(event_store::EventStore::create(&path, SESSION), "create store");
    let mut runtime = must_ok(
        Runtime::new(PolicySet, initial_state(), InProcessHost, store),
        "runtime",
    );
    assert_eq!(
        state_json(&runtime),
        INITIAL_STATE_CANONICAL,
        "the initial state must start frozen"
    );
    let event = must_ok(runtime.execute(Instruction::nop()), "execute nop");
    assert_eq!(event.sequence, 0);
    match &event.outcome {
        HandlerOutcome::Completed { evidence_ref } => {
            let expected = must_ok(
                StateHash::compute(SCHEMA_VERSION, HashAlg::Blake3, NOP_PAYLOAD),
                "recompute evidence from the frozen payload",
            );
            assert_eq!(
                *evidence_ref, expected.digest,
                "evidence is the digest of the raw payload (D15)"
            );
        }
        _ => panic!("the governed NOP must complete"),
    }
    let expected_policy_hash = must_ok(PolicySet.hash(HashAlg::Blake3), "policy hash");
    assert_eq!(event.policy_set_hash, expected_policy_hash);
    assert_eq!(
        state_json(&runtime),
        FINAL_STATE_CANONICAL,
        "the committed state is frozen from day one"
    );
    let session = must_ok(event_store::load(&path), "load");
    assert_eq!(session.name, SESSION);
    assert_eq!(session.pairs.len(), 1);
    assert_eq!(session.pairs[0].event.sequence, 0);
    assert!(
        session.pairs[0].record.prev_hash.is_none(),
        "the first record is genesis"
    );
}

#[test]
fn rejection_leaves_state_frozen() {
    let path = temp_path("rejected");
    let store = must_ok(event_store::EventStore::create(&path, SESSION), "create store");
    let mut runtime = must_ok(
        Runtime::new(PolicySet, initial_state(), InProcessHost, store),
        "runtime",
    );
    let denied = Instruction {
        kind: NOP_KIND.to_string(),
        capability: "state.write".to_string(),
        args: CanonicalValue::Map(BTreeMap::new()),
    };
    let event = must_ok(runtime.execute(denied), "execute denied");
    assert_eq!(event.sequence, 0);
    match &event.outcome {
        HandlerOutcome::Rejected { reason } => assert!(reason.contains("capability gate")),
        _ => panic!("the gate must reject before execution"),
    }
    assert_eq!(
        state_json(&runtime),
        INITIAL_STATE_CANONICAL,
        "Gate C must leave state unchanged"
    );
    assert_eq!(must_ok(event_store::load(&path), "load").pairs.len(), 1);
}
