// Negative fixture: unconstrained fn but no assert_eq! or constrain inside.
// Only runtime operations; no misfired constraint check.
use dep::std;

unconstrained fn compute_sqrt_hint(x: Field) -> Field {
    // Pure computation hint — no assert inside
    let mut guess: Field = x;
    for _ in 0..50 {
        guess = (guess + x / guess) / 2;
    }
    guess
}

fn safe_sqrt(x: Field) -> Field {
    let root = compute_sqrt_hint(x);
    // Constraint is in the constrained caller (correct pattern)
    assert(root * root == x);
    root
}

fn main(x: pub Field) -> pub Field {
    safe_sqrt(x)
}
