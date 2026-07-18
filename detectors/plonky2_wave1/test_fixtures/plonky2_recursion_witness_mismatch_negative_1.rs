// Negative fixture: virtual proof target created AND set_proof_with_pis_target
// is called AND verifier_data is connected. Properly wired recursion — no mismatch.
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::iop::witness::PartialWitness;
use plonky2::field::goldilocks_field::GoldilocksField;

type F = GoldilocksField;
const D: usize = 2;

pub fn build_recursive_circuit_good(
    inner_common_data: &CommonCircuitData<F, D>,
    inner_proof: &ProofWithPublicInputs<F, C, D>,
) {
    let mut builder = CircuitBuilder::<F, D>::new(Default::default());

    // Virtual proof target created
    let inner_proof_t = builder.add_virtual_proof_with_pis(inner_common_data);
    // Verifier data is connected to a constant (trusted) verifier — properly bound
    let trusted_vd = builder.constant_verifier_data(&inner_circuit_data);
    builder.connect_verifier_data(&inner_vd_t, &trusted_vd);

    let data = builder.build::<PoseidonGoldilocksConfig>();

    let mut pw = PartialWitness::new();
    // Properly set the proof witness — no mismatch
    pw.set_proof_with_pis_target(&inner_proof_t, inner_proof);
    pw.set_verifier_data_target(&inner_vd_t, &inner_circuit_data.verifier_only);

    let _proof = data.prove(pw).unwrap();
}
