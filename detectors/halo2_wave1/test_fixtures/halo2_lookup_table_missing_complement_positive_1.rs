// Positive: lookup body references a multi-byte `word` expression but
// looks it up against a single-byte (1 << 8) table.
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, TableColumn};

pub fn configure<F: Field>(meta: &mut ConstraintSystem<F>) {
    let word = meta.advice_column();
    let u8_table = meta.lookup_table_column();

    meta.lookup("missing_complement", |meta| {
        let w = meta.query_advice(word, Rotation::cur());
        let table = meta.query_lookup(u8_table);
        // word is multi-byte (u64 alias), table size is 1 << 8.
        // Half the input bits will be unconstrained.
        let table_size = 1 << 8;
        vec![(w, table)]
    });
}
