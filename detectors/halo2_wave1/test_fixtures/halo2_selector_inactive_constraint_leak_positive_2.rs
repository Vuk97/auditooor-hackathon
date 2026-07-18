// Positive #2: gate has selector but one of two expressions is bare
// (no selector applied).
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Selector, Expression};

pub fn configure<F: Field>(meta: &mut ConstraintSystem<F>) {
    let x = meta.advice_column();
    let y = meta.advice_column();
    let s_active = meta.selector();

    meta.create_gate("bare_constraint", |meta| {
        let sa = meta.query_selector(s_active);
        let qx = meta.query_advice(x, Rotation::cur());
        let qy = meta.query_advice(y, Rotation::cur());
        vec![
            sa * qx.clone(),
            qy - qx, // BUG: applied always
        ]
    });
}
