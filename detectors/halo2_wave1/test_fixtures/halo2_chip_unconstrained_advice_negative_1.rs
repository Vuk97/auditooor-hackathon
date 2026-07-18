// Negative: both advice columns referenced in gate body.
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Selector};

pub struct GoodChip {
    pub tag_value: Column<Advice>,
    pub tag_index: Column<Advice>,
    pub s: Selector,
}

impl GoodChip {
    pub fn configure<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let tag_value = meta.advice_column();
        let tag_index = meta.advice_column();
        let s = meta.selector();
        meta.create_gate("both_constrained", |meta| {
            let s = meta.query_selector(s);
            let tv = meta.query_advice(tag_value, Rotation::cur());
            let ti = meta.query_advice(tag_index, Rotation::cur());
            vec![s.clone() * tv, s * ti]
        });
        Self { tag_value, tag_index, s }
    }

    pub fn synthesize<F: Field>(&self, layouter: &mut impl Layouter<F>, v: F) -> Result<(), Error> {
        layouter.assign_region(|| "row", |mut region| {
            region.assign_advice(|| "tag_value", self.tag_value, 0, || Value::known(v))?;
            region.assign_advice(|| "tag_index", self.tag_index, 0, || Value::known(F::ZERO))?;
            Ok(())
        })
    }
}
