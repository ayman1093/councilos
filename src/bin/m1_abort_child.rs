//! M1 abort handler child: consumes one request frame, then raises SIGABRT.

use std::io::{self, Read};

fn main() -> io::Result<()> {
    let mut stdin_buf = Vec::new();
    io::stdin().read_to_end(&mut stdin_buf)?;

    let request = match councilos_kernel::instruction::Instruction::deserialize_canonical(&stdin_buf) {
        Ok(req) => req,
        Err(e) => {
            eprintln!("m1_abort_child: failed to deserialize request: {e}");
            std::process::exit(1);
        }
    };

    eprintln!(
        "m1_abort_child: session {} seq {} aborting deliberately",
        request.session_id, request.sequence
    );

    // Raise SIGABRT to test abnormal termination governance.
    #[cfg(unix)]
    {
        unsafe {
            libc::raise(libc::SIGABRT);
        }
    }

    #[cfg(not(unix))]
    {
        std::process::abort();
    }
}
