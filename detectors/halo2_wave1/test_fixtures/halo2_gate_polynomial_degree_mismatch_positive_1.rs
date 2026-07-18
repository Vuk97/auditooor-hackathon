// Positive: gate body has chained multiplication degree 5 (>3 threshold)
// AND lacks any meta.set_minimum_degree statement.
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Selector, Expression};

pub fn configure<F: Field>(meta: &mut ConstraintSystem<F>) {
    let a = meta.advice_column();
    let b = meta.advice_column();
    let c = meta.advice_column();
    let d = meta.advice_column();
    let e = meta.advice_column();
    let f_col = meta.advice_column();
    let s = meta.selector();

    meta.create_gate("high_degree", |meta| {
        let s = meta.query_selector(s);
        let qa = meta.query_advice(a, Rotation::cur());
        let qb = meta.query_advice(b, Rotation::cur());
        let qc = meta.query_advice(c, Rotation::cur());
        let qd = meta.query_advice(d, Rotation::cur());
        let qe = meta.query_advice(e, Rotation::cur());
        let qf = meta.query_advice(f_col, Rotation::cur());
        // Degree 5: s * a * b * c * d * e
        vec![s * qa * qb * qc * qd * qe * qf]
    });
}
