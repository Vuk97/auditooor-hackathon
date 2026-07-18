// Positive fixture: verify_proof_in_circuit called but inner verifier_data
// is not connected to outer public inputs. The verifier key is unbound.
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::field::goldilocks_field::GoldilocksField;

type F = GoldilocksField;
const D: usize = 2;

pub fn build_aggregator_bad(inner_common_data: &CommonCircuitData<F, D>) {
    let mut builder = CircuitBuilder::<F, D>::new(Default::default());

    let inner_proof_t = builder.add_virtual_proof_with_pis(inner_common_data);
    let inner_vd_t = builder.add_virtual_verifier_data(inner_common_data.config.fri_config.cap_height);

    // verify_proof called but inner_vd_t is never connected to outer PIs
    builder.verify_proof_in_circuit(&inner_proof_t, &inner_vd_t, inner_common_data);

    // BUG: should also do something like:
    // let expected_vd = builder.constant_verifier_data(&trusted_inner_data);
    // builder.connect_verifier_data(&inner_vd_t, &expected_vd);
    // But that connect is missing — malicious prover can substitute inner_vd.
}
