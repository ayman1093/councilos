//! The handler boundary for M1.
//!
//! Traceability: M1.md §2 ("HandlerHost trait — one trait, two implementations");
//! decisions D6 and D7 (signed 2026-10-27).
//!
//! # Contract
//!
//! - One handler invocation per instruction (per-call spawn; no pooling).
//! - The Runtime hashes and wraps evidence; the handler never sees a hash and
//!   never produces one.
//! - `HandlerRequest.deadline_ms` is metadata only — it travels outside the hash
//!   preimage, exactly like `Event.recorded_at_unix_ms`. Handlers may use it to
//!   bound their own work but must not emit it as evidence.
//! - Handler-internal errors (bad arguments, unsupported operations) are
//!   signaled by returning a payload of the shape
//!   `{"status":"error","reason":"..."}`. The runtime records this as
//!   `HandlerOutcome::Completed` (a handler response, not a governance
//!   rejection). The world of outcomes is closed per `event.rs:40-61`.
//! - Crash outcomes (`HostError::Crashed`) and timeouts are recorded as
//!   ordinary events, never as exceptions that escape the runtime
//!   (`M1.md:40`).
//! - Protocol violations (`HostError::Protocol`) trigger child kill
//!   (`SIGKILL = 9`), `wait()`, and a `Crashed { signal: Some(9), exit_code: None }`
//!   record (D7). Details go to stderr for operator visibility, never to the
//!   log. **Honesty caveat (D7):** `signal = 9` does not prove the runtime was
//!   the killer — an OS OOM killer delivers the same signal. The runtime's
//!   stderr line, not the code, is the operative attribution.

use crate::instruction::Instruction;

/// An outbound request to a handler.
#[derive(Debug, Clone)]
pub struct HandlerRequest {
    /// The instruction to execute.
    pub instruction: Instruction,
    /// Wall-clock budget for this call, in milliseconds.
    ///
    /// Metadata only. Provided by the runtime. Handlers should treat it as
    /// advisory; the runtime enforces it post-hoc by checking wall-clock
    /// elapsed time after the call returns (M1 is fully synchronous — no
    /// pre-emption, `M1.md:38`).
    pub deadline_ms: u64,
}

/// An inbound reply from a handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandlerReply {
    /// Handler completed. `payload` is the exact byte sequence the handler
    /// emitted, and it is hashed verbatim by the runtime:
    /// `evidence_ref = StateHash::compute(0, Blake3, payload).digest`
    /// (decision D15). No re-serialization is allowed — the bytes here are
    /// the bytes hashed.
    Finished {
        /// Raw payload bytes as emitted by the handler.
        payload: Vec<u8>,
    },
}

/// A failure of the host boundary, distinct from any instruction outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostError {
    /// Framing or protocol violation.
    ///
    /// The runtime kills the child (`SIGKILL = 9`) and records
    /// `Crashed { signal: Some(9), exit_code: None }`. Details go to stderr,
    /// never to the log (surfaced, never swallowed — `M1.md:40`). Note:
    /// `signal = 9` is not proof of attribution; an OS OOM killer delivers
    /// the same signal.
    Protocol {
        /// Human-readable reason.
        reason: String,
    },
    /// I/O failure on the pipe or process handle.
    Io {
        /// Human-readable reason.
        reason: String,
    },
    /// Handler process died.
    ///
    /// `signal = Some(6)` establishes SIGABRT (Gate B).
    /// `signal = Some(9)` may be the runtime's own kill or an OS-level
    /// delivery — the surrounding runtime action determines attribution.
    /// «SIGKILL=9 لا تثبت أن الـruntime هو القاتل (قاتل OOM يصل بنفسها)»
    Crashed {
        /// Terminating signal if reported by the OS.
        signal: Option<i32>,
        /// Exit code if reported by the OS.
        exit_code: Option<i32>,
    },
    /// Budget exceeded.
    ///
    /// **Not produced by M1 host implementations.** In M1 the runtime decides
    /// timeouts by evaluating the lease after `run()` returns (post-hoc, no
    /// pre-emption). Reserved — as signed under D7 — for M2+ where pre-emptive
    /// timeout becomes possible.
    Timeout,
}

/// The trait implemented by host backends.
///
/// # Implementations (deferred to subsequent P1 packages)
///
/// - `InProcessHost` (P1.3): fast tests, panic-only isolation
///   (`M1.md:12` — limitations are a documented contract).
/// - `SubprocessHost` (P1.4): separate OS process, length-prefixed JSON frames,
///   `SIGKILL = 9` on protocol violation, SIGABRT detection for Gate B.
pub trait HandlerHost {
    /// Execute one instruction.
    fn run(&mut self, request: &HandlerRequest) -> Result<HandlerReply, HostError>;
}
