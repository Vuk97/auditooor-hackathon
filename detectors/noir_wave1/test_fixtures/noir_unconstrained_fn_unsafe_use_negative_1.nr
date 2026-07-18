// Negative fixture: unconstrained inverse hint properly constrained.
// The result is asserted before use.
use dep::std;

unconstrained fn compute_inverse_hint(x: Field) -> Field {
    x.invert()
}

fn safe_inverse_use(x: Field) {
    let inv = compute_inverse_hint(x);
    // Properly constrained: assert that x * inv == 1 before using inv
    assert(x * inv == 1);
    // Now inv is circuit-constrained; safe to use
    let _ = inv;
}
