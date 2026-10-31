//! The **only** module in the crate permitted to read the wall clock.
//!
//! Traceability: decisions D8 + D14 (signed 2026-10-27); CLAUDE.md rule 4
//! ("No wall-clock time or randomness inside hashable state. recorded_at_unix_ms
//! is metadata, excluded from every hash.").
//!
//! # Contract
//!
//! - `clippy.toml` bans `SystemTime::now` and `Instant::now` crate-wide. This
//!   module is the single place where the ban is lifted, per-function, with
//!   `#[allow(clippy::disallowed_methods)]`. The allow MUST NOT be lifted to
//!   module or crate scope (`lib.rs:26` denies at crate level, `forbid` semantics
//!   don't apply — this is `deny`, so per-function allow is legal here and ONLY
//!   here).
//! - Values produced here never enter a hash preimage. They serve two purposes:
//!   (a) `Event.recorded_at_unix_ms`, which is metadata; (b) lease budgets,
//!   which are runtime-side quantities evaluated post-hoc.
//! - M1 is fully synchronous with no pre-emption. A blocked handler blocks the
//!   runtime until it returns or dies; the deadline is classified **after** the
//!   call, never to cancel one in flight.

/// Current wall-clock unix milliseconds.
///
/// **Metadata only.** Destination: `Event.recorded_at_unix_ms`, which is
/// excluded from every hash (see `event.rs` module invariants).
#[allow(clippy::disallowed_methods)]
pub(crate) fn unix_ms() -> u64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => u64::try_from(d.as_millis()).unwrap_or(u64::MAX),
        Err(_) => 0,
    }
}

/// A wall-clock budget attached to a single handler invocation.
///
/// See module docs for the M1 semantics of "post-hoc evaluation".
pub(crate) struct Deadline {
    start: std::time::Instant,
    budget: std::time::Duration,
}

impl Deadline {
    /// Arm a deadline of `budget_ms` milliseconds from the present instant.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn new(budget_ms: u64) -> Self {
        Deadline {
            start: std::time::Instant::now(),
            budget: std::time::Duration::from_millis(budget_ms),
        }
    }

    /// Whether the budget has been exceeded as of the call to `expired()`.
    pub(crate) fn expired(&self) -> bool {
        self.start.elapsed() > self.budget
    }
}
