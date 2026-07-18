// Negative: each region has a unique literal name.
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::Error;

pub fn ok<F: Field>(layouter: &mut impl Layouter<F>) -> Result<(), Error> {
    layouter.assign_region(|| "process_row_a", |mut region| {
        region.assign_advice(|| "x", region.x, 0, || Value::known(F::ZERO))
    })?;
    layouter.assign_region(|| "process_row_b", |mut region| {
        region.assign_advice(|| "y", region.y, 0, || Value::known(F::ONE))
    })?;
    Ok(())
}
