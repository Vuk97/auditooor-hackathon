// Negative #2: lookup against a properly-sized 1 << 16 table for a
// `word` input. No mismatch.
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem};

pub fn configure<F: Field>(meta: &mut ConstraintSystem<F>) {
    let word = meta.advice_column();
    let u16_table = meta.lookup_table_column();

    meta.lookup("word_in_u16", |meta| {
        let w = meta.query_advice(word, Rotation::cur());
        let t = meta.query_lookup(u16_table);
        let _ = 1 << 16; // not 1 << 8
        vec![(w, t)]
    });
}
