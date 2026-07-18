// Negative: every expression multiplies the selector.
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Selector, Expression};

pub fn configure<F: Field>(meta: &mut ConstraintSystem<F>) {
    let a = meta.advice_column();
    let b = meta.advice_column();
    let s = meta.selector();

    meta.create_gate("all_selected", |meta| {
        let s = meta.query_selector(s);
        let qa = meta.query_advice(a, Rotation::cur());
        let qb = meta.query_advice(b, Rotation::cur());
        vec![
            s.clone() * qa.clone() * (qa - Expression::Constant(F::ONE)),
            s * qb.clone() * (qb - Expression::Constant(F::ONE)),
        ]
    });
}
