// Negative fixture: all virtual targets are properly constrained via connect
// or arithmetic operations. No unconstrained targets.
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::field::goldilocks_field::GoldilocksField;

type F = GoldilocksField;
const D: usize = 2;

pub fn build_good_circuit() {
    let mut builder = CircuitBuilder::<F, D>::new(Default::default());

    let a = builder.add_virtual_target();
    let b = builder.add_virtual_target();

    // Both targets are properly constrained via arithmetic
    let sum = builder.add(a, b);
    let product = builder.mul(a, b);

    // And connected to public inputs
    builder.register_public_input(sum);
    builder.register_public_input(product);

    // Enforce a == b via connect (additional constraint)
    builder.connect(a, b);
}
