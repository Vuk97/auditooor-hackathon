// Positive fixture: virtual target `secret` is added but never connected
// or used in any arithmetic constraint. Classic unconstrained target.
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;

pub fn build_bad_circuit<F: RichField + Extendable<D>, const D: usize>() {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // This target is added but NEVER constrained (no connect, no arithmetic use)
    let secret = builder.add_virtual_target();

    // Only `pub_input` is constrained
    let pub_input = builder.add_virtual_target();
    let doubled = builder.add(pub_input, pub_input);
    builder.register_public_input(doubled);

    // `secret` never appears in connect / gate calls
    let _ = secret; // suppress Rust unused warning only
    let _data = builder.build::<PlonkConfig>();
}
