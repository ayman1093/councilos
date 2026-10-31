//! The replay child binary: prints the final state hash of a session file
//! given as its sole command-line argument, exiting zero on success.
//!
//! Driven by `tests/m1_replay.rs` to prove cross-process agreement between
//! the parent process's in-memory replay and an independent OS process.

use councilos_kernel::policy::PolicySet;
use councilos_kernel::replay::replay_session;

fn main() {
    let path = match std::env::args().nth(1) {
        Some(path) => path,
        None => {
            eprintln!("usage: m1_replay_child <session.jsonl>");
            std::process::exit(2);
        }
    };
    let replayed = match replay_session(&path, PolicySet) {
        Ok(replayed) => replayed,
        Err(error) => {
            eprintln!("replay failed: {error}");
            std::process::exit(1);
        }
    };
    print!("{}", replayed.final_state_hash.to_hex());
}
