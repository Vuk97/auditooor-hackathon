// Positive fixture: compute_inverse is unconstrained; its result `inv`
// is used directly in arithmetic without an assert constraint.
use dep::std;

unconstrained fn compute_inverse(x: Field) -> Field {
    // Hint: compute inverse outside circuit
    x.invert()
}

fn verify_product(x: Field, expected: Field) {
    // BUG: result of unconstrained fn used without constraint
    let inv = compute_inverse(x);
    // Missing: assert(x * inv == 1); or assert(inv == expected);
    // The prover can set inv to anything — circuit does not enforce x*inv==1
    let product = x * inv;
    assert(product == expected); // wrong: this asserts product==expected, not that inv is correct
}
