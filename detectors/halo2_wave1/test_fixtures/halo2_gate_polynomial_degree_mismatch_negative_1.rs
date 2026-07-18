// Negative: low-degree gate (degree 2) with selector.
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Selector};

pub fn configure<F: Field>(meta: &mut ConstraintSystem<F>) {
    let a = meta.advice_column();
    let b = meta.advice_column();
    let s = meta.selector();

    meta.create_gate("low_degree", |meta| {
        let s = meta.query_selector(s);
        let qa = meta.query_advice(a, Rotation::cur());
        let qb = meta.query_advice(b, Rotation::cur());
        // Degree 2: s * (a - b)
        vec![s * (qa - qb)]
    });
}
