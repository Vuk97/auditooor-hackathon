// Noir fixture for workspace-coverage-heatmap .nr function enumeration.
// Exercises plain `fn`, `pub fn`, and `unconstrained fn` shapes.

pub fn verify_proof(commitment: Field, mask: u64) -> bool {
    commitment != 0 & mask
}

fn hash_inputs(a: Field, b: Field) -> Field {
    a + b
}

unconstrained fn debug_dump(x: Field) {
    println(x);
}
