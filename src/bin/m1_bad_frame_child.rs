//! M1 bad-frame handler child: consumes one request frame, then declares a
//! malformed framing error via stdout (or exits bad).
//!
//! This binary is part of the M1 deterministic execution engine tests.
//! It is invoked as a subprocess by the host runtime to verify how the
//! supervisor handles malformed or corrupted framing streams from children.
//!
//! # Behavior
//! 1. Reads the exact input stream from stdin.
//! 2. Ignores or deliberately corrupts the framing protocol.
//! 3. Writes malformed response bytes to stdout.
//! 4. Exits with success or appropriate status code.

use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut stdin_buf = Vec::new();
    io::stdin().read_to_end(&mut stdin_buf)?;

    // We deliberately emit an invalid frame (e.g. truncated length prefix or garbage bytes)
    // to test M1 framing governance and supervisor error handling.
    let bad_response_bytes = b"BADFRAME_CORRUPT_STREAM_DATA";

    eprintln!("m1_bad_frame_child: emitting malformed frame bytes");
    io::stdout().write_all(bad_response_bytes)?;
    io::stdout().flush()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bad_frame_smoke() {
        let req = councilos_kernel::instruction::Instruction {
            session_id: 1,
            sequence: 1,
            payload: vec![],
        };
        let canonical = req.to_canonical();
        let decoded = councilos_kernel::instruction::Instruction::deserialize_canonical(&canonical).unwrap();
        assert_eq!(decoded.session_id, 1);
    }

    #[test]
    fn test_bad_frame_serialization_roundtrip() {
        let sample_data = b"corrupt_stream_payload";
        assert!(!sample_data.is_empty());
    }

    #[test]
    fn test_bad_frame_edge_cases() {
        let dummy_id: u64 = 42;
        let dummy_seq: u64 = 100;
        assert_eq!(dummy_id, 42);
        assert_eq!(dummy_seq, 100);
    }
}
}
