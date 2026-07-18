// Positive #2: region "comparator" reused twice (typical
// ComparatorChip reuse bug shape).
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::Error;

pub fn synthesize<F: Field>(layouter: &mut impl Layouter<F>) -> Result<(), Error> {
    layouter.assign_region(|| "comparator", |mut region| {
        region.assign_advice(|| "lhs", region.lhs, 0, || Value::known(F::ZERO))
    })?;
    self.layouter.assign_region(|| "comparator", |mut region| {
        region.assign_advice(|| "rhs", region.rhs, 0, || Value::known(F::ONE))
    })?;
    Ok(())
}
