// Positive fixture: advice column `tag_value` is assigned via
// region.assign_advice but never referenced in any gate body.
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Selector};

pub struct BadChip {
    pub tag_value: Column<Advice>,
    pub tag_index: Column<Advice>,
    pub s: Selector,
}

impl BadChip {
    pub fn configure<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let tag_value = meta.advice_column();
        let tag_index = meta.advice_column();
        let s = meta.selector();
        meta.create_gate("tag_index_only", |meta| {
            let s = meta.query_selector(s);
            let ti = meta.query_advice(tag_index, Rotation::cur());
            vec![s * ti]  // tag_value is NEVER referenced here
        });
        Self { tag_value, tag_index, s }
    }

    pub fn synthesize<F: Field>(&self, layouter: &mut impl Layouter<F>, value: F) -> Result<(), Error> {
        layouter.assign_region(|| "row", |mut region| {
            region.assign_advice(|| "tag_value", self.tag_value, 0, || Value::known(value))?;
            region.assign_advice(|| "tag_index", self.tag_index, 0, || Value::known(F::ZERO))?;
            Ok(())
        })
    }
}
