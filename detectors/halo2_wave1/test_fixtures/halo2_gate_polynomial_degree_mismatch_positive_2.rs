// Positive #2: gate has no selector multiplier — always-on constraint.
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Expression};

pub fn configure<F: Field>(meta: &mut ConstraintSystem<F>) {
    let a = meta.advice_column();
    let b = meta.advice_column();

    meta.create_gate("always_on", |meta| {
        let qa = meta.query_advice(a, Rotation::cur());
        let qb = meta.query_advice(b, Rotation::cur());
        // No selector queried: constraint applies on every row.
        vec![qa - qb]
    });
}
