// Negative fixture 1: proper error handling in RISC Zero guest — no finding.
#![no_main]
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let input: Vec<u8> = env::read();

    // Proper error handling: match on result, commit error code if invalid.
    match bincode::deserialize::<u64>(&input) {
        Ok(value) => {
            let result = value.wrapping_mul(2);
            env::commit(&result);
        }
        Err(_) => {
            // Commit an error sentinel instead of panicking.
            env::commit(&u64::MAX);
        }
    }
}
