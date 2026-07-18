// Positive fixture: Poseidon sponge state accessed at index 8 (capacity region).
// This directly reads a capacity element, breaking the sponge security.
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::field::goldilocks_field::GoldilocksField;

type F = GoldilocksField;
const D: usize = 2;

pub fn build_leaky_poseidon_circuit() {
    let mut builder = CircuitBuilder::<F, D>::new(Default::default());

    let inputs: Vec<_> = (0..8).map(|_| builder.add_virtual_target()).collect();

    // Apply poseidon
    let hash_out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs.clone());

    // BUG: access state[8] — this is a capacity element (index >= RATE=8)
    // In a real circuit this would be state[8] directly; here we simulate with
    // a separate capacity buffer that the circuit leaks.
    let state = [
        inputs[0], inputs[1], inputs[2], inputs[3],
        inputs[4], inputs[5], inputs[6], inputs[7],
        // capacity elements: indices 8, 9, 10, 11
        hash_out.elements[0], hash_out.elements[1], hash_out.elements[2], hash_out.elements[3],
    ];
    // BUG: reading capacity lane directly and exposing as public input
    let leaked_capacity = state[8]; // index 8 >= RATE (8)
    builder.register_public_input(leaked_capacity);
}
