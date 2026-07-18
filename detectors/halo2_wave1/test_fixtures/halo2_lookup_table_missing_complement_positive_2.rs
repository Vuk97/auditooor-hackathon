// Positive #2: lookup of an `address` (20-byte) value against a
// 1 << 8 byte table.
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem};

pub fn configure<F: Field>(meta: &mut ConstraintSystem<F>) {
    let address = meta.advice_column();
    let byte_table = meta.lookup_table_column();

    meta.lookup_any("addr_byte_table", |meta| {
        let a = meta.query_advice(address, Rotation::cur());
        let t = meta.query_lookup(byte_table);
        // input is `address` (20 bytes); table is u8_table (1 << 8).
        let _ = 1 << 8;
        vec![(a, t)]
    });
}
