// Positive: region name "process_row" used in 3 distinct assign_region
// call sites within the same chip.
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::Error;

pub fn run<F: Field>(layouter: &mut impl Layouter<F>) -> Result<(), Error> {
    layouter.assign_region(|| "process_row", |mut region| {
        region.assign_advice(|| "col_a", region.col_a, 0, || Value::known(F::ZERO))
    })?;
    layouter.assign_region(|| "process_row", |mut region| {
        region.assign_advice(|| "col_b", region.col_b, 0, || Value::known(F::ONE))
    })?;
    layouter.assign_region(|| "process_row", |mut region| {
        region.assign_advice(|| "col_c", region.col_c, 0, || Value::known(F::ONE))
    })?;
    Ok(())
}
