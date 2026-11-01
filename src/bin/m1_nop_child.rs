//! M1 NOP handler child: reads one request frame, replies `ok`, exits 0.

use councilos_kernel::hex;
use councilos_kernel::instruction::{Instruction, Response};
use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut stdin_buf = Vec::new();
    io::stdin().read_to_end(&mut stdin_buf)?;

    let request = match Instruction::deserialize_canonical(&stdin_buf) {
        Ok(req) => req,
        Err(e) => {
            eprintln!("m1_nop_child: failed to deserialize request: {e}");
            std::process::exit(1);
        }
    };

    let session_id = request.session_id;
    let sequence = request.sequence;

    let response = Response {
        session_id,
        sequence,
        result: Ok("ok".to_string()),
        state_hash: hex::encode(&[0u8; 32]),
    };

    let canonical_bytes = response.to_canonical();
    io::stdout().write_all(&canonical_bytes)?;
    io::stdout().flush()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nop_child_smoke() {
        let req = Instruction {
            session_id: 1,
            sequence: 1,
            payload: vec![],
        };
        let canonical = req.to_canonical();
        let decoded = Instruction::deserialize_canonical(&canonical).unwrap();
        assert_eq!(decoded.session_id, 1);
        assert_eq!(decoded.sequence, 1);
    }
}

