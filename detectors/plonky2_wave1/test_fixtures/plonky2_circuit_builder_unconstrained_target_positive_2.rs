// Positive fixture: `nullifier_hash` virtual target added but only used
// in witness set_target — never in any circuit constraint. Prover can set
// any value and the circuit won't reject it.
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::iop::witness::PartialWitness;
use plonky2::field::goldilocks_field::GoldilocksField;

type F = GoldilocksField;
const D: usize = 2;

pub fn build_nullifier_circuit() {
    let mut builder = CircuitBuilder::<F, D>::new(Default::default());

    let commitment = builder.add_virtual_target();
    let nullifier_hash = builder.add_virtual_target(); // never constrained

    // Only commitment is constrained
    let c2 = builder.mul(commitment, commitment);
    builder.register_public_input(c2);

    // nullifier_hash appears only in pw.set_target, not in builder constraints
    let mut pw = PartialWitness::new();
    pw.set_target(commitment, F::from_canonical_u64(42));
    pw.set_target(nullifier_hash, F::from_canonical_u64(999)); // unconstrained
}
