// Negative: lookup body uses a single-byte input against a 1 << 8 table.
// Correct sizing — no missing complement.
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem};

pub fn configure<F: Field>(meta: &mut ConstraintSystem<F>) {
    let lo_byte = meta.advice_column();
    let u8_table = meta.lookup_table_column();

    meta.lookup("byte_ok", |meta| {
        let b = meta.query_advice(lo_byte, Rotation::cur());
        let t = meta.query_lookup(u8_table);
        let _ = 1 << 8;
        vec![(b, t)]
    });
}
