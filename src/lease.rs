//! The M1 resource lease.
//!
//! Traceability: M1.md §2 ("resource lease (acquire → execute → release)");
//! decision D8 (signed 2026-10-27): time-only lease, post-hoc evaluation,
//! timeout budget lives outside hashable state.
//!
//! # M1 semantics
//!
//! For the single `Nop` instruction the lease is a wall-clock budget only: the
//! runtime arms a deadline before execution and evaluates it after. No
//! contention exists in M1, so `acquire` cannot fail; `Lease` itself is the
//! acquisition, and dropping it is the release (no cleanup is needed because
//! no shared resource is held — the fields are a pure `Instant` + `Duration`).
//!
//! `Lease` MUST NOT be stored inside any hashable structure. It carries an
//! `Instant` which cannot be serialized and must not be.

use crate::clock::Deadline;

/// Wall-clock budget granted to one `Nop` handler invocation, in milliseconds.
///
/// 5 seconds is a generous ceiling for a no-op handler. Any actual timeout is
/// a symptom of a buggy or blocked handler; the runtime will record
/// `HandlerOutcome::TimedOut` when the budget is exceeded.
pub const NOP_LEASE_MS: u64 = 5_000;

/// A live lease held across one handler invocation.
#[must_use]
pub struct Lease {
    deadline: Deadline,
}

impl Lease {
    /// Acquire a lease. Cannot fail under the M1 fixed policy.
    pub fn acquire() -> Self {
        Lease {
            deadline: Deadline::new(NOP_LEASE_MS),
        }
    }

    /// Whether the lease budget has already been exceeded.
    pub fn expired(&self) -> bool {
        self.deadline.expired()
    }
}
