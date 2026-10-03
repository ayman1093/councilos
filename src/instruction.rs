//! Instruction: the unit of governed execution.
//!
//! Traceability:
//!   - handover doc §1 (project), §2 ("التسلسل: sequence لا UUID"،
//!     "الحوكمة عند حدود الثقة الأربعة"), §4-ب (M0 scope)
//!   - ADR-0001 (canonical serialization, schema 0; hash layout)
//!   - RFC-001 §2 (instruction contract)
//!   - Milestone: M0 (silent skeleton) — data contract + hashing only
//!   - Test matrix: T-M0-INS-01 (wire round-trip), T-M0-INS-02 (wire
//!     stability), T-M0-INS-03 (canonical form frozen), T-M0-INS-04 (hash)
//!   - Independent review: v0/Claude fresh-session review (fixed the
//!     `serde_json::Error: PartialEq` test bug; suggested NOP constants)
//!
//! Invariants (enforced here, relied on by `event`, `state`, `m0_golden`):
//!   1. An instruction carries **intent only**: kind + capability + args.
//!     No timestamps, no random ids, no host data. Identity and time live
//!     on the enclosing `Event`.
//!   2. The wire format is a contract. `kind`, `capability` and `args` keys
//!     are frozen at first release: never renamed, never removed. Adding a
//!     field is a minor change; changing an existing one is a SCHEMA VERSION
//!     bump (ADR-0001 §Versioning).
//!   3. The canonical form (`to_canonical`) is the ONLY input to hashing —
//!     never serde's struct-field ordering. The canonical JSON for `Nop` is
//!     pinned byte-exact by `tests/m0_golden.rs`:
//!       {"args":{},"capability":"kernel.nop","kind":"nop"}
//!   4. `args` is a `CanonicalValue::Map` — closed universe (no floats, no
//!     random-iteration collections), so the whole instruction is hashable
//!     by construction. Non-map args are rejected loudly, never coerced.
//!   5. `Nop` is `is_pure() == true`: it can never mutate governed state.
//!   6. DESIGN DECISION (M0): `kind: String` is open — the wire accepts any
//!     kind, `is_pure()` returns `false` for anything but `NOP_KIND`. M1's
//!     capability gate closes this: unknown kinds are rejected before
//!     execution. Recorded here so it is a decision, not an accident.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::state::{CanonicalError, CanonicalValue, HashAlg, StateHash};

/// Wire tag of the `Nop` instruction. Frozen contract (invariant 2).
pub const NOP_KIND: &str = "nop";
/// Capability required to execute `Nop`. Frozen contract (invariant 2).
pub const NOP_CAPABILITY: &str = "kernel.nop";

/// A single governed instruction submitted to the kernel.
///
/// Every instruction must pass policy → capability → resource lease before
/// execution (RFC-001 §3). `Nop` exists to exercise the complete governance
/// path with zero side effects; M1's acceptance tests are built on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    /// Stable wire tag identifying the instruction kind (see `NOP_KIND`).
    pub kind: String,
    /// The capability this instruction requires of its executor.
    /// Checked at the capability gate, never trusted from the agent's claim.
    pub capability: String,
    /// Closed-universe arguments. Must be `CanonicalValue::Map`; the empty
    /// map canonicalizes to `{}` and stays hash-stable.
    pub args: CanonicalValue,
}

impl Instruction {
    /// The canonical `Nop` instruction.
    ///
    /// The three field values are pinned by golden hashes in
    /// `tests/m0_golden.rs`; change any of them and the goldens break —
    /// by design.
    pub fn nop() -> Self {
        Instruction {
            kind: NOP_KIND.to_string(),
            capability: NOP_CAPABILITY.to_string(),
            args: CanonicalValue::Map(BTreeMap::new()),
        }
    }

    /// `true` if executing this instruction can never mutate governed state.
    ///
    /// Purity is a property of the intent (invariant 5). The list grows one
    /// instruction at a time — deliberately, never by convention.
    pub fn is_pure(&self) -> bool {
        matches!(self.kind.as_str(), NOP_KIND)
    }

    /// Canonical form used for hashing (ADR-0001, schema 0).
    ///
    /// `BTreeMap` ordering (`args` < `capability` < `kind`, bytewise) matches
    /// the frozen golden byte sequence exactly (invariant 3).
    pub fn to_canonical(&self) -> Result<CanonicalValue, CanonicalError> {
        if !matches!(&self.args, CanonicalValue::Map(_)) {
            return Err(CanonicalError::ArgsMustBeMap);
        }
        let mut m = BTreeMap::new();
        m.insert("args".to_string(), self.args.clone());
        m.insert("capability".to_string(), CanonicalValue::Str(self.capability.clone()));
        m.insert("kind".to_string(), CanonicalValue::Str(self.kind.clone()));
        Ok(CanonicalValue::Map(m))
    }

    /// Hash of the canonical form under `alg` — the instruction's own
    /// versioned digest (see `Event::hash` for the enclosing record).
    pub fn hash(&self, alg: HashAlg) -> Result<StateHash, CanonicalError> {
        self.to_canonical()?.hash(alg)
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // kind is the human-facing name; capability is the policy-facing
        // name. One contract, three views: Display, wire, canonical.
        write!(f, "{}({})", self.kind, self.capability)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T-M0-INS-01 / T-M0-INS-02: wire round-trip AND frozen wire format.
    /// The wire JSON is a contract (invariant 2): changing this string is a
    /// schema bump, never an in-place edit.
    #[test]
    fn nop_round_trips_with_frozen_wire_format() {
        let original = Instruction::nop();

        let json = serde_json::to_string(&original).map_err(|e| e.to_string());
        assert_eq!(
            json,
            Ok(r#"{"kind":"nop","capability":"kernel.nop","args":{}}"#.to_string())
        );

        // Map errors to String: `serde_json::Error` is not `PartialEq`,
        // so the Result cannot be compared directly with `assert_eq!`
        // (independent-review finding).
        let back = serde_json::from_str::<Instruction>(
            r#"{"kind":"nop","capability":"kernel.nop","args":{}}"#,
        )
        .map_err(|e| e.to_string());
        assert_eq!(back, Ok(original));
    }

    /// T-M0-INS-03: the canonical form is frozen, byte-exact.
    /// This is the exact preimage `tests/m0_golden.rs` pins a BLAKE3 digest
    /// for; any change here changes the golden hash (invariant 3).
    #[test]
    fn nop_canonical_form_is_frozen_byte_exact() {
        let canon = Instruction::nop()
            .to_canonical()
            .map(|c| c.to_canonical_json());
        assert_eq!(
            canon,
            Ok(r#"{"args":{},"capability":"kernel.nop","kind":"nop"}"#.to_string())
        );
    }

    /// T-M0-INS-04: hashing produces the versioned layout (schema 0, alg
    /// 0x01). The exact 68-hex digest is pinned by `m0_golden`.
    #[test]
    fn nop_hash_has_versioned_layout() {
        let h = Instruction::nop()
            .hash(HashAlg::Blake3)
            .map(|h| h.to_bytes());
        match h {
            Ok(bytes) => {
                assert_eq!(bytes[0], crate::SCHEMA_VERSION);
                assert_eq!(bytes[1], HashAlg::Blake3.id());
            }
            Err(e) => panic!("blake3 must be available in M0: {e:?}"),
        }
    }

    /// Non-map args are a contract violation: rejected loudly at the
    /// canonical boundary, never silently coerced (invariant 4).
    #[test]
    fn non_map_args_fail_at_canonicalization() {
        let bad = Instruction {
            kind: NOP_KIND.to_string(),
            capability: NOP_CAPABILITY.to_string(),
            args: CanonicalValue::Int(7),
        };
        assert!(matches!(
            bad.to_canonical(),
            Err(CanonicalError::ArgsMustBeMap)
        ));
    }

    /// Purity is a property of the intent, pinned per-kind (invariant 5).
    #[test]
    fn nop_is_pure_by_definition() {
        assert!(Instruction::nop().is_pure());
        let other = Instruction {
            kind: "write_state".to_string(),
            capability: "state.write".to_string(),
            args: CanonicalValue::Map(BTreeMap::new()),
        };
        assert!(!other.is_pure());
    }
}
