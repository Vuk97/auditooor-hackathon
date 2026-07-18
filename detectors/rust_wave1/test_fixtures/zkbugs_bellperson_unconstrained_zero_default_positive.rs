use bellperson::{ConstraintSystem, SynthesisError};
use bellperson::gadgets::num::AllocatedNum;
use ff::Field;

fn selector_dot_product<Scalar: Field, CS: ConstraintSystem<Scalar>>(
    _cs: CS,
    _selectors: &[AllocatedNum<Scalar>],
    _cases: &[AllocatedNum<Scalar>],
    _default: AllocatedNum<Scalar>,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    unimplemented!()
}

pub fn vulnerable_default<Scalar: Field, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    selectors: &[AllocatedNum<Scalar>],
    cases: &[AllocatedNum<Scalar>],
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let zero = AllocatedNum::alloc(cs.namespace(|| "default zero"), || Ok(Scalar::zero()))?;
    selector_dot_product(cs.namespace(|| "select"), selectors, cases, zero.clone())
}
