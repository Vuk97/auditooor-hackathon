// Positive fixture: add_virtual_proof_with_pis creates `inner_proof` but
// pw.set_proof_with_pis_target is never called. Witness mismatch.
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::iop::witness::PartialWitness;

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

pub fn build_recursive_circuit_bad(common_data: &CommonCircuitData<F, D>) {
    let mut builder = CircuitBuilder::<F, D>::new(Default::default());

    // Virtual proof target created
    let inner_proof = builder.add_virtual_proof_with_pis(common_data);
    builder.verify_proof_in_circuit(&inner_proof, &inner_vd, common_data);

    // Public inputs registered
    builder.register_public_inputs(&inner_proof.public_inputs);

    let data = builder.build::<C>();

    // Missing: pw.set_proof_with_pis_target(&inner_proof, &actual_proof)
    // This means the witness for inner_proof is never assigned properly.
    let mut pw = PartialWitness::new();
    // pw.set_proof_with_pis_target(&inner_proof, &real_proof); // MISSING
    let _proof = data.prove(pw).unwrap();
}
