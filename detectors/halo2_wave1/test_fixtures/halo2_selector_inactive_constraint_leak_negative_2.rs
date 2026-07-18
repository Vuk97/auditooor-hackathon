// Negative #2: Constraints::with_selector wraps the vec — externally
// gated; detector should suppress.
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Constraints, Selector, Expression};

pub fn configure<F: Field>(meta: &mut ConstraintSystem<F>) {
    let a = meta.advice_column();
    let b = meta.advice_column();
    let s = meta.selector();

    meta.create_gate("external_select", |meta| {
        let s = meta.query_selector(s);
        let qa = meta.query_advice(a, Rotation::cur());
        let qb = meta.query_advice(b, Rotation::cur());
        Constraints::with_selector(s, vec![
            qa.clone() * (qa - Expression::Constant(F::ONE)),
            qb.clone() * (qb - Expression::Constant(F::ONE)),
        ])
    });
}
