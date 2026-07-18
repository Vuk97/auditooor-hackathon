// Positive fixture 1: .unwrap() on user-supplied data in zkVM guest.
#![no_main]
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

pub fn main() {
    // Read a value from the host (attacker-controlled).
    let input: Vec<u8> = env::read();

    // BUG: .unwrap() on attacker-controlled input — prover can abort
    // proof generation by supplying None / Err variant.
    let value: u64 = bincode::deserialize(&input).unwrap();

    // Commit the result to the journal.
    env::commit(&value);
}
