// Negative fixture 2: plain Rust file with .unwrap() but not a RISC Zero guest.
use std::fs;

fn read_config(path: &str) -> String {
    // This is a normal Rust binary, not a zkVM guest.
    // .unwrap() here is a conventional (if sloppy) error handling choice,
    // but the risc0 detector should NOT fire on non-guest files.
    fs::read_to_string(path).unwrap()
}
