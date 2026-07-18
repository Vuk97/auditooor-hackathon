// Positive fixture #2: column `padding_flag` assigned but never gated.
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Selector};

pub struct PaddingChip {
    pub padding_flag: Column<Advice>,
    pub byte: Column<Advice>,
    pub s: Selector,
}

impl PaddingChip {
    pub fn configure<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let padding_flag = meta.advice_column();
        let byte = meta.advice_column();
        let s = meta.selector();
        meta.create_gate("byte_only", |meta| {
            let s = meta.query_selector(s);
            let b = meta.query_advice(byte, Rotation::cur());
            vec![s * b * (b - Expression::Constant(F::from(255u64)))]
        });
        Self { padding_flag, byte, s }
    }

    pub fn assign<F: Field>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(|| "padding", |mut region| {
            region.assign_advice(|| "padding_flag", self.padding_flag, 0, || Value::known(F::ONE))?;
            region.assign_advice(|| "byte", self.byte, 0, || Value::known(F::ZERO))?;
            Ok(())
        })
    }
}
