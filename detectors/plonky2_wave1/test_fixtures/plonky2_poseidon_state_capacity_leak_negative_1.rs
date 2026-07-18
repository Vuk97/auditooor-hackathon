// Negative fixture: Poseidon hash used correctly, only rate-region elements
// accessed. State indexing stays within 0..7. No capacity leak.
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::field::goldilocks_field::GoldilocksField;

type F = GoldilocksField;
const D: usize = 2;

pub fn build_safe_poseidon_circuit() {
    let mut builder = CircuitBuilder::<F, D>::new(Default::default());

    let inputs: Vec<_> = (0..8).map(|_| builder.add_virtual_target()).collect();
    let hash_out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs.clone());

    // Only access rate-region elements (indices 0..3, which are the 4 hash output elements)
    for elem in &hash_out.elements {
        builder.register_public_input(*elem);
    }

    // Safe: state accessed only in indices 0..7
    let safe_state = [inputs[0], inputs[1], inputs[2], inputs[3], inputs[4], inputs[5]];
    let s0 = safe_state[0]; // index 0 < RATE — OK
    let s7 = safe_state[5]; // index 5 < RATE — OK
    let _ = (s0, s7);
}
