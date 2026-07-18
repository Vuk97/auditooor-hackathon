// Positive: 3 constraints in vec!, only first multiplies by selector.
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Selector, Expression};

pub fn configure<F: Field>(meta: &mut ConstraintSystem<F>) {
    let a = meta.advice_column();
    let b = meta.advice_column();
    let c = meta.advice_column();
    let s = meta.selector();

    meta.create_gate("onehot_like", |meta| {
        let s = meta.query_selector(s);
        let qa = meta.query_advice(a, Rotation::cur());
        let qb = meta.query_advice(b, Rotation::cur());
        let qc = meta.query_advice(c, Rotation::cur());
        vec![
            s.clone() * (qa.clone() + qb.clone() + qc.clone() - Expression::Constant(F::ONE)),
            qa.clone() * (qa - Expression::Constant(F::ONE)),  // BUG: no selector
            qb * (qb - Expression::Constant(F::ONE)),           // BUG: no selector
        ]
    });
}
