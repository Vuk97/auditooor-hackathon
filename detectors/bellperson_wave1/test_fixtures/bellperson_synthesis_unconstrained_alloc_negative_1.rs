// Negative fixture 1: `a` and `b` both appear in cs.enforce — no finding.
use bellperson::{ConstraintSystem, SynthesisError};
use bls12_381::Scalar;

fn synthesize<CS: ConstraintSystem<Scalar>>(cs: &mut CS) -> Result<(), SynthesisError> {
    let a = cs.alloc(|| "a", || Ok(Scalar::one()))?;
    let b = cs.alloc(|| "b", || Ok(Scalar::one()))?;
    let c = cs.alloc(|| "c", || Ok(Scalar::one()))?;

    // a * b = c is properly enforced.
    cs.enforce(
        || "a * b = c",
        |lc| lc + a,
        |lc| lc + b,
        |lc| lc + c,
    );
    Ok(())
}
