//! M1 abort handler child: consumes one request frame, then raises SIGABRT.
//!
//! This binary belongs to the P1.4 test surface of `SubprocessHost` and is
//! the real killer required by Gate B: `std::process::abort()` raises
//! SIGABRT (6) in the operating system itself — no simulated crash, no
//! panic, no exit code pretending to be a signal.
//!
//! Order matters and is signed: the request frame is consumed in full
//! first, so the parent's write succeeds and the only variable left is the
//! child's death. The host then observes the signal from `wait` directly
//! (signed D7; the honesty sentence lives on `HostError::Crashed`).
//!
//! Wire contract (must match `src/subprocess_host.rs`): `u32` big-endian
//! length header, then exactly that many payload bytes. This child never
//! replies — dying by signal is its whole report.

use std::io::{self, Read};

fn main() {
    let _consumed = consume_request_frame(io::stdin());
    std::process::abort();
}

/// Consume one request frame from stdin without keeping its payload.
///
/// Mirrors the NOP child exactly: a truncated request is not an error here,
/// because every outcome is decided by the host from the child's fate, not
/// from anything the child reports.
fn consume_request_frame(mut stdin: impl Read) -> io::Result<u64> {
    let mut header = [0u8; 4];
    stdin.read_exact(&mut header)?;
    let length = u64::from(u32::from_be_bytes(header));
    io::copy(&mut stdin.take(length), &mut io::sink())
}
