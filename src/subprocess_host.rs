//! Subprocess handler host: one governed handler per call, a real OS process.
//!
//! Every [`HandlerHost::run`] spawns a fresh child, writes one request frame
//! to its stdin, reads at most one reply frame from its stdout, drains its
//! stderr, and records the child's fate as an outcome — never as a raised
//! panic. Per the signed model, a crash is a recorded event.
//!
//! # Wire protocol (M1)
//!
//! A frame is a `u32` big-endian length header followed by exactly that many
//! payload bytes. The request payload is the canonical JSON of the
//! instruction; the reply payload is the raw bytes whose digest becomes
//! `evidence_ref` (see [`crate::host::HandlerReply`]). `deadline_ms` never
//! travels on the wire: `HandlerRequest` is metadata-only and the lease is
//! enforced post-hoc by the runtime (signed D8 note).
//!
//! Frame limit: [`MAX_FRAME_BYTES`] (1 MiB). A request payload above the
//! limit is rejected as `Protocol` before any child is spawned — unreachable
//! in M1 through the NOP instruction. A reply whose declared length exceeds
//! the limit is detected before any allocation, then the child is sent
//! `SIGKILL` (9), waited, and reported as `Crashed` exactly as `wait`
//! observed it — no fabricated fields (signed D7).
//!
//! # Classification order (signed)
//!
//! Signal first, then exit code, then reply completeness:
//!
//! - died by signal → `Crashed { signal: Some(s), exit_code: None }`
//! - exited non-zero → `Crashed { signal: None, exit_code: Some(code) }`
//! - exited 0, reply incomplete → `Protocol`
//! - exited 0, reply complete → `Finished { payload }`
//!
//! A spawn failure is [`HostError::Io`] and nothing else, so the runtime
//! turns it into `SpawnFailed` and the lease is released by scope exit
//! (signed correction: no outcome event is fabricated for a process that
//! never started).
//!
//! # Honest limits (M1)
//!
//! - stderr is piped, drained after `wait`, printed to the parent's stderr
//!   only on failure, never hashed, and never enters any `reason` string —
//!   it cannot reach the JSONL log.
//! - The child's stderr pipe holds 64 KiB: handlers are expected to stay
//!   nearly silent (the M1 children are).
//! - There is no pre-emption: the call waits synchronously, and a child that
//!   neither writes nor exits would block it (post-hoc lease limit, D8).
//!   M1 children always terminate.
//! - Unix-only (`ExitStatusExt`), matching the M1 CI target.
//! - `SIGKILL=9` does not prove the runtime was the killer — an OOM killer
//!   arrives with the same signal. The signed honesty statement lives on
//!   [`HostError::Crashed`].

use std::io::{Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};

use crate::host::{HandlerHost, HandlerReply, HandlerRequest, HostError};

/// Maximum size of one wire frame payload in bytes: 1 MiB.
///
/// Signed D15 note: `evidence_ref` is a hex digest carried inside canonical
/// JSON, so a raw handler payload occupies roughly twice its size on the
/// wire — a payload near this limit stands for about 512 KiB of raw bytes.
pub const MAX_FRAME_BYTES: usize = 1 << 20;

/// Fixed reason for a death that `wait` could not describe.
const UNKNOWN_STATUS_REASON: &str = "وفاة بتفاصيل مجهولة تُسجَّل حدثاً، لا تُرفع";

/// Fixed reason for an instruction that cannot be canonicalized.
const CANONICALIZATION_REASON: &str = "instruction cannot be canonicalized";

/// Fixed reason for a request payload above [`MAX_FRAME_BYTES`].
const OVERSIZED_REQUEST_REASON: &str = "request payload exceeds the frame limit";

/// Fixed reason for a payload length that does not fit the wire header.
const FRAME_WIDTH_REASON: &str = "request payload length exceeds the frame field width";

/// Fixed reason for an exit without a complete reply.
const INCOMPLETE_REPLY_REASON: &str = "handler exited without a complete reply";

/// A handler host that runs every call as a fresh child process.
#[derive(Debug, Clone)]
pub struct SubprocessHost {
    program: PathBuf,
}

impl SubprocessHost {
    /// Build a host that spawns `program` for every call.
    ///
    /// The path is not checked at construction: a missing or non-executable
    /// program surfaces as [`HostError::Io`] from the first `run`, which the
    /// runtime maps to `SpawnFailed` (signed correction — a spawn failure
    /// never fabricates an outcome event).
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
        }
    }

    /// Spawn one child with all three standard streams piped.
    fn spawn(&self) -> Result<Child, HostError> {
        Command::new(&self.program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            // `io::Error` implements `Display` through its `Error` impl; the
            // reason is operator-facing and never reaches the JSONL log.
            .map_err(|error| HostError::Io {
                reason: format!("failed to spawn handler process: {error}"),
            })
    }
}

impl HandlerHost for SubprocessHost {
    fn run(&mut self, request: &HandlerRequest) -> Result<HandlerReply, HostError> {
        let payload = request_payload(request)?;
        let length = frame_length(payload.len())?;
        let mut child = self.spawn()?;
        send_frame(&mut child, length, &payload);
        let reply = read_reply(&mut child);
        let outcome = match reply {
            ReplyRead::OverLimit => {
                // D7: kill, wait, and report exactly what `wait` observed.
                let _killed = child.kill();
                let status = child.wait().map_err(|_| HostError::Protocol {
                    reason: UNKNOWN_STATUS_REASON.to_string(),
                })?;
                Err(crashed_as_observed(status))
            }
            reply => classify(child.wait(), reply),
        };
        let stderr_bytes = drain_stderr(&mut child);
        if outcome.is_err() && !stderr_bytes.is_empty() {
            eprintln!(
                "subprocess handler stderr ({} bytes):\n{}",
                stderr_bytes.len(),
                String::from_utf8_lossy(&stderr_bytes)
            );
        }
        outcome
    }
}

/// Build the canonical request payload, rejecting what cannot be framed.
fn request_payload(request: &HandlerRequest) -> Result<Vec<u8>, HostError> {
    let canonical = request
        .instruction
        .to_canonical()
        .map_err(|_| HostError::Protocol {
            reason: CANONICALIZATION_REASON.to_string(),
        })?;
    let payload = canonical.to_canonical_json().into_bytes();
    if payload.len() > MAX_FRAME_BYTES {
        return Err(HostError::Protocol {
            reason: OVERSIZED_REQUEST_REASON.to_string(),
        });
    }
    Ok(payload)
}

/// Represent a checked payload length as the wire `u32` header value.
fn frame_length(payload_len: usize) -> Result<u32, HostError> {
    u32::try_from(payload_len).map_err(|_| HostError::Protocol {
        reason: FRAME_WIDTH_REASON.to_string(),
    })
}

/// Write one request frame to the child's stdin, then close the pipe.
fn send_frame(child: &mut Child, length: u32, payload: &[u8]) {
    if let Some(mut stdin) = child.stdin.take() {
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(payload);
        // A failed write means the handler closed stdin early — typically
        // because it has already died. The death is classified from `wait`;
        // the write error itself is not surfaced as `Io` because the spawn
        // succeeded and no reply can be trusted either way.
        let _written = stdin.write_all(&frame);
        // Dropping `stdin` closes the pipe: the handler observes EOF.
    }
}

/// Read at most one reply frame from the child's stdout.
fn read_reply(child: &mut Child) -> ReplyRead {
    match child.stdout.take() {
        Some(stdout) => read_frame(stdout),
        // Unreachable: stdout is piped at spawn. Treated as an incomplete
        // reply so the child's fate still decides the classification.
        None => ReplyRead::Incomplete,
    }
}

/// What came back on the handler's stdout before `wait`.
enum ReplyRead {
    /// A complete frame: the declared length arrived in full.
    Complete(Vec<u8>),
    /// EOF or a short read before a complete frame.
    Incomplete,
    /// Declared length above [`MAX_FRAME_BYTES`]; detected before allocation.
    OverLimit,
}

/// Parse one frame from `reader`, checking the limit before any allocation.
fn read_frame(mut reader: impl Read) -> ReplyRead {
    let mut length_bytes = [0u8; 4];
    if reader.read_exact(&mut length_bytes).is_err() {
        return ReplyRead::Incomplete;
    }
    // `u32 as usize` is lossless wherever M1 runs (usize is at least 32 bits).
    let declared = u32::from_be_bytes(length_bytes) as usize;
    if declared > MAX_FRAME_BYTES {
        return ReplyRead::OverLimit;
    }
    let mut payload = vec![0u8; declared];
    if reader.read_exact(&mut payload).is_err() {
        return ReplyRead::Incomplete;
    }
    ReplyRead::Complete(payload)
}

/// Classify the child's fate with the signed priority order.
fn classify(
    status: std::io::Result<ExitStatus>,
    reply: ReplyRead,
) -> Result<HandlerReply, HostError> {
    let status = status.map_err(|_| HostError::Protocol {
        reason: UNKNOWN_STATUS_REASON.to_string(),
    })?;
    if let Some(signal) = status.signal() {
        return Err(HostError::Crashed {
            signal: Some(signal),
            exit_code: None,
        });
    }
    match status.code() {
        Some(0) => match reply {
            ReplyRead::Complete(payload) => Ok(HandlerReply::Finished { payload }),
            ReplyRead::Incomplete | ReplyRead::OverLimit => Err(HostError::Protocol {
                reason: INCOMPLETE_REPLY_REASON.to_string(),
            }),
        },
        Some(code) => Err(HostError::Crashed {
            signal: None,
            exit_code: Some(code),
        }),
        None => Err(HostError::Protocol {
            reason: UNKNOWN_STATUS_REASON.to_string(),
        }),
    }
}

/// Build a `Crashed` from exactly what `wait` observed — no fabrication.
fn crashed_as_observed(status: ExitStatus) -> HostError {
    match status.signal() {
        Some(signal) => HostError::Crashed {
            signal: Some(signal),
            exit_code: None,
        },
        None => HostError::Crashed {
            signal: None,
            exit_code: status.code(),
        },
    }
}

/// Drain the child's stderr after `wait`: diagnostics only, never hashed.
fn drain_stderr(child: &mut Child) -> Vec<u8> {
    let mut bytes = Vec::new();
    if let Some(mut stderr) = child.stderr.take() {
        // A read failure cannot change the classification: stderr is
        // operator-facing only, never enters any `reason`, never the log.
        let _drained = stderr.read_to_end(&mut bytes);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use crate::instruction::{Instruction, NOP_CAPABILITY, NOP_KIND};
    use crate::state::CanonicalValue;

    fn request_with(args: CanonicalValue) -> HandlerRequest {
        HandlerRequest {
            instruction: Instruction {
                kind: NOP_KIND.to_string(),
                capability: NOP_CAPABILITY.to_string(),
                args,
            },
            deadline_ms: 0,
        }
    }

    #[test]
    fn max_frame_bytes_is_one_mib() {
        assert_eq!(MAX_FRAME_BYTES, 1_048_576);
    }

    #[test]
    fn oversized_request_is_rejected_before_spawn() {
        let mut huge = BTreeMap::new();
        let _inserted = huge.insert("x".to_string(), CanonicalValue::Str("x".repeat(MAX_FRAME_BYTES + 1)));
        let request = request_with(CanonicalValue::Map(huge));
        let mut host = SubprocessHost::new("/nonexistent/councilos/p1-4-oversized");
        match host.run(&request) {
            Err(HostError::Protocol { reason }) => {
                assert_eq!(reason, OVERSIZED_REQUEST_REASON);
            }
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    #[test]
    fn missing_program_surfaces_io_not_protocol() {
        let request = request_with(CanonicalValue::Map(BTreeMap::new()));
        let mut host = SubprocessHost::new("/nonexistent/councilos/p1-4-missing");
        match host.run(&request) {
            Err(HostError::Io { .. }) => {}
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn read_frame_reads_a_complete_frame() {
        let bytes = [0u8, 0, 0, 2, b'o', b'k'];
        match read_frame(&bytes[..]) {
            ReplyRead::Complete(payload) => assert_eq!(payload, vec![b'o', b'k']),
            _ => panic!("expected a complete frame"),
        }
    }

    #[test]
    fn read_frame_flags_over_limit_before_allocating() {
        let bytes = u32::MAX.to_be_bytes();
        match read_frame(&bytes[..]) {
            ReplyRead::OverLimit => {}
            _ => panic!("expected the over-limit verdict"),
        }
    }

    #[test]
    fn read_frame_flags_truncated_input() {
        let bytes = [0u8, 0, 0, 4, b'o', b'k']; // declared 4, sent 2
        match read_frame(&bytes[..]) {
            ReplyRead::Incomplete => {}
            _ => panic!("expected the incomplete verdict"),
        }
    }

    /// SIGABRT on Linux — documented locally, no `libc` dependency.
    const SIGABRT: i32 = 6;

    #[test]
    fn classify_signal_is_crashed_with_signal_only() {
        match classify(Ok(ExitStatus::from_raw(SIGABRT)), ReplyRead::Incomplete) {
            Err(HostError::Crashed { signal, exit_code }) => {
                assert_eq!(signal, Some(SIGABRT));
                assert_eq!(exit_code, None);
            }
            other => panic!("expected a signal crash, got {other:?}"),
        }
    }

    #[test]
    fn classify_nonzero_exit_is_crashed_with_exit_code_only() {
        match classify(Ok(ExitStatus::from_raw(3 << 8)), ReplyRead::Incomplete) {
            Err(HostError::Crashed { signal, exit_code }) => {
                assert_eq!(signal, None);
                assert_eq!(exit_code, Some(3));
            }
            other => panic!("expected an exit-code crash, got {other:?}"),
        }
    }

    #[test]
    fn classify_clean_exit_with_complete_reply_is_finished() {
        match classify(Ok(ExitStatus::from_raw(0)), ReplyRead::Complete(vec![b'o', b'k'])) {
            Ok(HandlerReply::Finished { payload }) => assert_eq!(payload, vec![b'o', b'k']),
            other => panic!("expected a finished reply, got {other:?}"),
        }
    }

    #[test]
    fn classify_clean_exit_with_incomplete_reply_is_protocol() {
        match classify(Ok(ExitStatus::from_raw(0)), ReplyRead::Incomplete) {
            Err(HostError::Protocol { reason }) => {
                assert_eq!(reason, INCOMPLETE_REPLY_REASON);
            }
            other => panic!("expected a protocol error, got {other:?}"),
        }
    }
}
