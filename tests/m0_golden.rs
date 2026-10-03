//! M0 golden hashes.
//!
//! Traceability: handover doc §4-ج; ADR-0001 (versioning & migration).
//!
//! This test pins the exact canonical bytes and BLAKE3 digests of the smallest
//! meaningful pipeline: NOP instruction -> completed event -> one-key state ->
//! genesis state record. It prints `GOLDEN: <name>=<hex>` lines; the
//! `cross-process-golden` CI job runs the binary twice in separate processes and
//! diffs the output.
//!
//! If any constant below changes, that is a **canon change**. The correct
//! response is NOT to update the constant: it is to bump `SCHEMA_VERSION`, keep
//! the old canonical path alive for replay, and add new goldens for the new
//! version (ADR-0001 §Migration).

use std::collections::BTreeMap;

use councilos_kernel::{
    CanonicalState, CanonicalValue, Event, HandlerOutcome, HashAlg, Instruction, StateRecord,
    SCHEMA_VERSION,
};

// ---- Golden constants (schema 0, BLAKE3) -------------------------------------
//
// 68 hex chars = [schema_version][alg][digest32]. Every value below starts with
// "0001": schema 0, algorithm 0x01 (BLAKE3).

const GOLDEN_NOP_INSTRUCTION_CANON: &str = r#"{"args":{},"capability":"kernel.nop","kind":"nop"}"#;
const GOLDEN_NOP_INSTRUCTION_HASH: &str =
    "0001c40327ff598b20245e6b9a2a4ebb70198cfc542c4a9de97c4efc53a0c7ea89b8";

const GOLDEN_EVENT_HASH: &str =
    "0001d6ddd398e5e46c622c5fce8342d09847f4c0ebc7fb5e4725918aebaea2d9c004";

const GOLDEN_STATE_CANON: &str = r#"{"last_sequence":0,"nop_count":1,"session":"m0-golden"}"#;
const GOLDEN_STATE_HASH: &str =
    "00018ff03b61e71776d36709ca3ae95984e101f901ebcedc040ddafb609ae0d23ff5";

const GOLDEN_STATE_RECORD_HASH: &str =
    "00019c21a5c22815110fdc9d49b59988f3e058c5555b80bb2482c7bc0a1ee4e77601";

// ---- Fixtures ----------------------------------------------------------------

fn fixture_event() -> Event {
    Event {
        sequence: 0,
        // Deliberately non-zero and "ugly": it must not influence any hash.
        recorded_at_unix_ms: 1_725_000_000_123,
        instruction: Instruction::nop(),
        outcome: HandlerOutcome::Completed {
            // Fixed, runtime-produced evidence digest for the golden fixture.
            evidence_ref: [0x5e; 32],
        },
        policy_set_hash: [0x9c; 32],
    }
}

fn fixture_state() -> CanonicalState {
    let mut s = BTreeMap::new();
    s.insert(
        "session".to_string(),
        CanonicalValue::Str("m0-golden".to_string()),
    );
    s.insert("nop_count".to_string(), CanonicalValue::Int(1));
    s.insert("last_sequence".to_string(), CanonicalValue::Int(0));
    s
}

fn hex_of<T: std::fmt::Display, E: std::fmt::Debug>(r: Result<T, E>) -> String {
    match r {
        Ok(h) => h.to_string(),
        Err(e) => panic!("hashing must not fail in the golden fixture: {e:?}"),
    }
}

fn emit(name: &str, value: &str) {
    println!("GOLDEN: {name}={value}");
}

// ---- Tests -------------------------------------------------------------------

#[test]
fn golden_schema_version() {
    emit("schema_version", &SCHEMA_VERSION.to_string());
    assert_eq!(SCHEMA_VERSION, 0, "M0 goldens are only valid for schema 0");
}

#[test]
fn golden_nop_instruction() {
    let i = Instruction::nop();
    let canon = match i.to_canonical() {
        Ok(c) => c.to_canonical_json(),
        Err(e) => panic!("{e}"),
    };
    let hash = hex_of(i.hash(HashAlg::Blake3));
    emit("nop_instruction_canon", &canon);
    emit("nop_instruction_hash", &hash);
    assert_eq!(canon, GOLDEN_NOP_INSTRUCTION_CANON);
    assert_eq!(hash, GOLDEN_NOP_INSTRUCTION_HASH);
}

#[test]
fn golden_event() {
    let e = fixture_event();
    let hash = hex_of(e.hash(HashAlg::Blake3));
    emit("event_hash", &hash);
    assert_eq!(hash, GOLDEN_EVENT_HASH);

    // Timestamp independence is part of the golden contract.
    let mut e2 = e.clone();
    e2.recorded_at_unix_ms = 0;
    assert_eq!(hex_of(e2.hash(HashAlg::Blake3)), GOLDEN_EVENT_HASH);
}

#[test]
fn golden_state() {
    let s = fixture_state();
    let canon = match councilos_kernel::state::canonical(&s) {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    let canon_json = canon.to_canonical_json();
    let hash = hex_of(canon.hash(HashAlg::Blake3));
    emit("state_canon", &canon_json);
    emit("state_hash", &hash);
    assert_eq!(canon_json, GOLDEN_STATE_CANON);
    assert_eq!(hash, GOLDEN_STATE_HASH);
}

#[test]
fn golden_state_record_genesis() {
    let s = fixture_state();
    let rec = match StateRecord::new(0, &s, None, HashAlg::Blake3) {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(rec.prev_hash, None);
    assert_eq!(rec.state_hash.to_hex(), GOLDEN_STATE_HASH);
    let rec_hash = hex_of(rec.to_canonical().hash(HashAlg::Blake3));
    emit("state_record_hash", &rec_hash);
    assert_eq!(rec_hash, GOLDEN_STATE_RECORD_HASH);
}

#[test]
fn golden_hashes_all_carry_schema_and_alg_prefix() {
    for h in [
        GOLDEN_NOP_INSTRUCTION_HASH,
        GOLDEN_EVENT_HASH,
        GOLDEN_STATE_HASH,
        GOLDEN_STATE_RECORD_HASH,
    ] {
        assert_eq!(h.len(), 68);
        assert!(
            h.starts_with("0001"),
            "expected schema 0 / alg 0x01 prefix: {h}"
        );
    }
      }
