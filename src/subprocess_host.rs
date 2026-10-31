//! Subprocess host implementation for M1.
//!
//! Spawns child processes and communicates via the defined wire protocol.

use std::process::{Command, Stdio};
use std::io::{self, Read, Write};

pub const NOP_PAYLOAD: &[u8] = b"ok";

pub struct SubprocessHost {
    program: String,
}

impl SubprocessHost {
    pub fn new(program: impl Into<String>) -> Self {
        Self { program: program.into() }
    }

    pub fn call(&self, request: &[u8]) -> io::Result<Vec<u8>> {
        let mut child = Command::new(&self.program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            let len_bytes = u32::try_from(request.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "request too large"))?
                .to_be_bytes();
            stdin.write_all(&len_bytes)?;
            stdin.write_all(request)?;
        }

        let output = child.wait_with_output()?;
        
        // Extract reply frame (u32 length + payload)
        if output.stdout.len() >= 4 {
            let _len = u32::from_be_bytes([
                output.stdout[0],
                output.stdout[1],
                output.stdout[2],
                output.stdout[3],
            ]);
            Ok(output.stdout[4..].to_vec())
        } else {
            Ok(vec![])
        }
    }
}
