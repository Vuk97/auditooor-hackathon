// Positive fixture: RATE constant redefined to 4 (below Plonky2 default of 8).
// This silently shrinks the rate boundary; circuits written for RATE=8 will
// access capacity elements starting at index 4.
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::circuit_builder::CircuitBuilder;

// BUG: RATE narrowed from default 8 to 4
const RATE: usize = 4;
const WIDTH: usize = 12;
const CAPACITY: usize = WIDTH - RATE; // now 8 instead of 4

pub fn build_circuit_with_narrow_rate() {
    // Code written assuming RATE=8 will now access capacity starting at index 4
    // Any sponge absorption loop using index < 8 will write into capacity region
    let mut state = [0u64; WIDTH];
    for i in 0..8 {
        state[i] = i as u64; // writes into capacity when i >= 4
    }
    // Use PoseidonHash to trigger the detector's poseidon-usage check
    let _hash = PoseidonHash::hash_no_pad(&[]);
}
