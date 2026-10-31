//! The fixed M1 policy set.
//!
//! Traceability: M1.md §2 ("single fixed policy set in M1"); decision D16
//! (signed 2026-10-27) — model (a): the executor holds the capability, the
//! instruction names it.
//!
//! # M1 rule set
//!
//! Exactly one rule is encoded: allow `kind = "nop"` iff the instruction
//! requires the capability `kernel.nop` and the executor declares that same
//! capability. Any other kind or capability is rejected at the gate.
//!
//! The canonical JSON of the policy set anchors every event in the session
//! through `Event::policy_set_hash`. Its preimage is built with
//! `CanonicalValue::map` — the checked constructor that enforces the `$`-key
//! rule (`state.rs:19-22`, the ADR-0002 known limitation). Building the
//! `BTreeMap` directly would bypass that guard.

use crate::instruction::{Instruction, NOP_CAPABILITY, NOP_KIND};
use crate::state::{CanonicalError, CanonicalValue, HashAlg};

/// The single fixed M1 policy set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicySet;

impl PolicySet {
    /// Canonical form used for hashing.
    ///
    /// The shape is stable and minimal: one allow rule with three fields.
    /// Any change here changes `Event::policy_set_hash` on every event and
    /// therefore invalidates every M1 session log — a schema-bump-level change
    /// per ADR-0001 §Versioning, not something to alter in place.
    pub fn to_canonical(self) -> Result<CanonicalValue, CanonicalError> {
        let allow_rule = CanonicalValue::map([
            ("allow", CanonicalValue::Bool(true)),
            ("capability", CanonicalValue::Str(NOP_CAPABILITY.to_string())),
            ("kind", CanonicalValue::Str(NOP_KIND.to_string())),
        ])?;
        CanonicalValue::map([("rules", CanonicalValue::Seq(vec![allow_rule]))])
    }

    /// The 32-byte digest written to `Event::policy_set_hash` on every event.
    ///
    /// **Shape:** `StateHash::compute(SCHEMA_VERSION, alg, canonical_json).digest`.
    /// Only the 32-byte digest is stored (`Event.policy_set_hash: Hash32`,
    /// `lib.rs:42-45`); the versioned 34-byte form is reserved for
    /// `StateHash`-typed fields (`StateRecord.state_hash`). This mirrors D15's
    /// treatment of `evidence_ref`.
    pub fn hash(self, alg: HashAlg) -> Result<[u8; 32], CanonicalError> {
        let canonical = self.to_canonical()?;
        let state_hash = canonical.hash(alg)?;
        Ok(state_hash.digest)
    }

    /// Capability gate: does the fixed policy permit this instruction?
    ///
    /// Mirrors the frozen rule byte-shape of [`PolicySet::to_canonical`]
    /// (`policy.rs:33-40`): one allow rule over `kind = "nop"` and
    /// `capability = "kernel.nop"`. There is no second source of truth: any
    /// change here must match a change there, and the frozen test at
    /// `policy.rs:61` fails otherwise.
    pub fn permits(self, instruction: &Instruction) -> bool {
        instruction.kind == NOP_KIND && instruction.capability == NOP_CAPABILITY
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_policy_is_frozen_byte_exact() {
        let canon = PolicySet.to_canonical().map(|c| c.to_canonical_json());
        let expected = concat!(
            "{\"rules\":[{",
            "\"allow\":true,",
            "\"capability\":\"kernel.nop\",",
            "\"kind\":\"nop\"",
            "}]}"
        );
        assert_eq!(canon, Ok(expected.to_string()));
    }

    #[test]
    fn policy_hash_is_deterministic() {
        let a = PolicySet.hash(HashAlg::Blake3);
        let b = PolicySet.hash(HashAlg::Blake3);
        assert_eq!(a, b);
        match a {
            Ok(digest) => assert_eq!(digest.len(), 32),
            Err(e) => panic!("blake3 must be available in M1: {e:?}"),
        }
    }

    #[test]
    fn policy_hash_rejects_sha256_reserved() {
        assert!(PolicySet.hash(HashAlg::Sha256).is_err());
    }
}
