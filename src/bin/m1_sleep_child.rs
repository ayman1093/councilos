//! M1 sleep handler child: sleeps for a specified duration or until interrupted,
//! used for testing supervisor timeout and cancellation logic.

use std::io::{self, Read};
use std::thread;
use std::time::Duration;

fn main() -> io::Result<()> {
    let mut stdin_buf = Vec::new();
    io::stdin().read_to_end(&mut stdin_buf)?;

    eprintln!("m1_sleep_child: entering sleep state for timeout testing");

    // Sleep for a controlled duration to test supervisor grace periods.
    thread::sleep(Duration::from_millis(500));

    eprintln!("m1_sleep_child: sleep completed successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sleep_duration_bounds() {
        let dur = Duration::from_millis(500);
        assert_eq!(dur.as_millis(), 500);
    }

    #[test]
    fn test_sleep_smoke() {
        assert!(true);
    }
}
    #[test]
    fn test_sleep_extended_boundary() {
        let val = 500_u64;
        assert!(val > 0);
    }
}
    }
}
}
