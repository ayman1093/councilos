//! M1 bad-frame handler child: consumes one request frame, then declares a
//! reply longer than the frame limit and waits to be killed.
//!
//! This binary belongs to the P1.4 test surface of `SubprocessHost`. It
//! exercises the signed D7 reply path: a declared reply length above the
//! 1 MiB limit must be detected by the host before any allocation, the
//! child must then be killed with SIGKILL (9), and the crash must be
//! reported exactly as `wait` observed it — `Crashed { signal: Some(9),
//! exit_code: None }`.
//!
//! The declared length below is `MAX_FRAME_BYTES + 1` where
//! `MAX_FRAME_BYTES` is `1 << 20` in `src/subprocess_host.rs`; the two
//! values are pinned to each other by this comment because the child never
//! links the library.
//!
//! Order matters: the request frame is consumed in full first (the parent's
//! write must succeed), then only the four header bytes of the oversized
//! reply are written — no payload follows. The child then sleeps, so the
//! parent's SIGKILL always wins the race and the observed signal is
//! deterministic.

use std::io::{self, Read, Write};
use std::time::Duration;

/// Declared reply length above the limit: 1 MiB + 1 bytes.
const OVERSIZED_DECLARED_LENGTH: u32 = (1 << 20) + 1;

/// How long the child outlives its bad header, waiting for SIGKILL.
///
/// A safety valve, not a delay on the normal path: the parent kills the
/// child within milliseconds of reading the header. The bound only keeps a
/// broken parent from leaving a stray process behind — M1 children always
/// terminate.
const HOLD_AFTER_HEADER_MS: u64 = 30_000;

fn main() {
    let _consumed = consume_request_frame(io::stdin());
    announce_oversized_reply();
    std::thread::sleep(Duration::from_millis(HOLD_AFTER_HEADER_MS));
}

/// Consume one request frame from stdin without keeping its payload.
///
/// Mirrors the other M1 children: every outcome is decided by the host
/// from the child's fate, not from anything the child reports.
fn consume_request_frame(mut stdin: impl Read) -> io::Result<u64> {
    let mut header = [0u8; 4];
    stdin.read_exact(&mut header)?;
    let length = u64::from(u32::from_be_bytes(header));
    io::copy(&mut stdin.take(length), &mut io::sink())
}

/// Write only the four header bytes of the oversized reply.
///
/// No payload follows: the host must reject on the declared length alone,
/// before allocating, per signed D7.
fn announce_oversized_reply() {
    let mut stdout = io::stdout();
    let header = OVERSIZED_DECLARED_LENGTH.to_be_bytes();
    let _written = stdout.write_all(&header);
    let _flushed = stdout.flush();
}
