//! # councilos-kernel — M0 "silent skeleton"
//!
//! Traceability: handover doc §1 (project), §2 (settled decisions), §4 (M0 scope).
//!
//! M0 contains **data contracts and hashing rules only**. There is no scheduler,
//! no runtime, no I/O, no policy engine and no host in this milestone. Everything
//! here exists so that M1 can be built on top of stable, golden-tested hashes.
//!
//! ## Invariants enforced at the crate boundary
//!
//! - **Determinism**: no `HashMap`/`HashSet` (clippy.toml), no floats
//!   (`clippy::float_arithmetic` denied below + `CanonicalValue` has no float
//!   variant), no wall-clock time inside hashable state (clippy.toml).
//! - **Hash layout**: `[schema_version: u8][alg: u8][digest: 32B]` — see
//!   [`state::StateHash`] and ADR-0001.
//! - **Schema version 0**: canonical JSON is the hash preimage. M1 switches to
//!   deterministic CBOR (RFC 8949 §4.2) under schema version 1; v0 is kept for
//!   replaying M0 sessions.
//! - **Sequence, not UUID**: every [`event::Event`] carries a `u64` sequence.
//! - **Time is metadata**: `Event.recorded_at_unix_ms` is excluded from all hashes.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::disallowed_types)]
#![deny(clippy::disallowed_methods)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![warn(clippy::all)]

pub mod event;
pub mod hex;
pub mod instruction;
pub mod state;

/// Canonical serialization schema version used for every hash produced by M0.
///
/// ADR-0001: schema 0 = canonical JSON (compact, keys sorted bytewise, no floats).
/// Schema 1 (deterministic CBOR) is introduced in M1 and MUST NOT reuse this value.
pub const SCHEMA_VERSION: u8 = 0;

/// A raw 32-byte digest, without version/algorithm prefix.
///
/// Used for `policy_set_hash`, `evidence_ref` and as the digest part of
/// [`state::StateHash`]. On the wire it is always hex via [`hex::array32`].
pub type Hash32 = [u8; 32];

pub use event::{Event, HandlerOutcome};
pub use instruction::Instruction;
pub use state::{CanonicalState, CanonicalValue, HashAlg, StateHash, StateRecord};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_is_zero_in_m0() {
        // Changing this constant changes every golden hash; it must be a
        // deliberate, reviewed decision (see tests/m0_golden.rs).
        assert_eq!(SCHEMA_VERSION, 0);
    }

    #[test]
    fn hash32_is_exactly_32_bytes() {
        assert_eq!(std::mem::size_of::<Hash32>(), 32);
    }
}
