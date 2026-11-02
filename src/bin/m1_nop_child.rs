//! M1 NOP handler child: reads one request frame, replies `ok`, exits 0.
//!
//! This binary belongs to the P1.4 test surface of `SubprocessHost`. It is
//! deliberately independent of the kernel library: it speaks the wire
//! protocol with `std` alone, never parses the request payload, and keeps
//! no state — one process, one call, one reply (signed D6 model).
//!
//! Wire contract (must match `src/subprocess_host.rs`):
//!
//! - request frame: `u32` big-endian length, then exactly that many bytes;
//! - the whole request frame is consumed before replying, so the parent's
//!   write cannot fail on a broken pipe on the happy path (EPIPE lesson);
//! - reply frame: `u32` big-endian length, then exactly `b"ok"`.
//!
//! The reply payload matches `NOP_PAYLOAD` in `src/in_process_host.rs`
//! byte for byte: the two hosts must agree on it, and the frozen golden in
//! `tests/m1_policy.rs` is the anchor that moves first if it ever changes.

use std::io::{self, Read, Write};

/// Reply payload — must match `NOP_PAYLOAD` in `src/in_process_host.rs`.
const REPLY: &[u8] = b"ok";

fn main() {
    let _consumed = consume_request_frame(io::stdin());
    write_reply_frame(REPLY);
}

/// Consume one request frame from stdin without keeping its payload.
///
/// A truncated request is not an error here: the host decides every
/// outcome, and this child still exits cleanly so the host classifies a
//! clean exit with an incomplete reply as protocol — never a fabricated
/// crash — per the signed classification order.
fn consume_request_frame(mut stdin: impl Read) -> io::Result<u64> {
    let mut header = [0u8; 4];
    stdin.read_exact(&mut header)?;
    let length = u64::from(u32::from_be_bytes(header));
    io::copy(&mut stdin.take(length), &mut io::sink())
}

/// Write one complete reply frame to stdout.
///
/// Write errors end quietly: the host classifies the outcome from `wait`,
/// never from anything this process reports about itself.
fn write_reply_frame(payload: &[u8]) {
    let length = match u32::try_from(payload.len()) {
        Ok(length) => length,
        Err(_) => return, // REPLY is two bytes; unreachable by construction
    };
    let mut stdout = io::stdout();
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    let _written = stdout.write_all(&frame);
    let _flushed = stdout.flush();
}
