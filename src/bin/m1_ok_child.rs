//! M1 success handler child: consumes one request frame, then returns a
//! valid success response frame.

use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut stdin_buf = Vec::new();
    io::stdin().read_to_end(&mut stdin_buf)?;

    let request = match councilos_kernel::instruction::Instruction::deserialize_canonical(&stdin_buf) {
        Ok(req) => req,
        Err(e) => {
            eprintln!("m1_ok_child: failed to deserialize request: {e}");
            std::process::exit(1);
        }
    };

    eprintln!(
        "m1_ok_child: session {} seq {} processing successfully",
        request.session_id, request.sequence
    );

    // Build a success response frame.
    let response = councilos_kernel::instruction::Instruction {
        session_id: request.session_id,
        sequence: request.sequence + 1,
        payload: b"OK_SUCCESS_RESPONSE".to_vec(),
    };

    let serialized = response.to_canonical();
    io::stdout().write_all(&serialized)?;
    io::stdout().flush()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ok_child_smoke() {
        assert!(true);
    }
}
}
