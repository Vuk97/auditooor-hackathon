// Positive fixture 2: panic! directly in guest code.
#![no_main]
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let count: u32 = env::read();
    if count == 0 {
        // BUG: panic in guest causes prover to abort — no proof emitted.
        panic!("count must be non-zero");
    }
    let result = count * 42;
    env::commit(&result);
}
