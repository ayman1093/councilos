//! The in-process host backend (P1.3).
//!
//! `InProcessHost` runs the single M1 handler — the deterministic NOP
//! payload — inside the runtime process: fast tests, panic-only isolation
//! (`host.rs:101-104`).
//!
//! Honest limits:
//!
//! - `catch_unwind` here isolates a panicking handler from the runtime. It is
//!   **not** a crash simulation and it does **not** serve Gate B: Gate B needs
//!   a real `abort()` (SIGABRT) in a real process — `SubprocessHost`, P1.4.
//!   A caught panic is reported as `HostError::Protocol` and recorded by the
//!   runtime as `Crashed { signal: None, exit_code: None }` (why `None` and
//!   not D7's `Some(9)` is explained in `runtime.rs`: D7's kill mapping is the
//!   subprocess host's — `host.rs:62-72`).
//! - The panic hook still prints details to stderr before unwinding: details
//!   are surfaced there and never enter the log (`host.rs:66-67`, `M1.md:40`).
//! - The payload bytes are frozen at P1.3: [`NOP_PAYLOAD`]. They feed the
//!   evidence preimage verbatim (D15, `host.rs:48-52`), so changing them
//!   changes every `evidence_ref` of every NOP — a schema-bump-level change
//!   per ADR-0001 §Versioning.
//! - The request is not inspected: the capability gate has already validated
//!   the instruction; a second gate here would be a second source of truth.

use crate::host::{HandlerHost, HandlerReply, HandlerRequest, HostError};

/// The exact payload bytes emitted by the M1 NOP handler.
///
/// Frozen from P1.3: these bytes are hashed verbatim into `evidence_ref`
/// (D15). Changing them is a schema-bump-level change.
pub const NOP_PAYLOAD: &[u8] = b"ok";

/// The in-process host backend: one deterministic handler, panic-isolated.
#[derive(Debug)]
pub struct InProcessHost;

fn nop_payload() -> Vec<u8> {
    NOP_PAYLOAD.to_vec()
}

impl InProcessHost {
    fn isolate<F>(handler: F) -> Result<Vec<u8>, HostError>
    where
        F: FnOnce() -> Vec<u8> + std::panic::UnwindSafe,
    {
        match std::panic::catch_unwind(handler) {
            Ok(payload) => Ok(payload),
            Err(_) => Err(HostError::Protocol {
                reason: "handler panicked inside the process".to_string(),
            }),
        }
    }
}

impl HandlerHost for InProcessHost {
    fn run(&mut self, _request: &HandlerRequest) -> Result<HandlerReply, HostError> {
        let payload = Self::isolate(nop_payload)?;
        Ok(HandlerReply::Finished { payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> HandlerRequest {
        HandlerRequest {
            instruction: crate::instruction::Instruction::nop(),
            deadline_ms: crate::lease::NOP_LEASE_MS,
        }
    }

    #[test]
    fn run_returns_the_frozen_payload() {
        let mut host = InProcessHost;
        match host.run(&request()) {
            Ok(HandlerReply::Finished { payload }) => {
                assert_eq!(payload.as_slice(), NOP_PAYLOAD);
            }
            Err(error) => panic!("the in-process host must complete: {error:?}"),
        }
    }

    #[test]
    fn panicking_handler_is_isolated_as_protocol() {
        match InProcessHost::isolate(|| -> Vec<u8> { panic!("deliberate handler panic") }) {
            Err(HostError::Protocol { reason }) => {
                assert!(reason.contains("panicked"));
            }
            other => panic!("expected an isolated Protocol error, got {other:?}"),
        }
    }
}
