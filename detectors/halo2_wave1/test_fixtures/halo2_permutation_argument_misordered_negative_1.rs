// Negative: both columns properly equality-enabled.
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem};

pub struct GoodTxChip {
    pub tx_id: Column<Advice>,
    pub chain_id: Column<Advice>,
}

impl GoodTxChip {
    pub fn configure<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let tx_id = meta.advice_column();
        let chain_id = meta.advice_column();
        meta.enable_equality(tx_id);
        meta.enable_equality(chain_id);
        Self { tx_id, chain_id }
    }

    pub fn link<F: Field>(&self, region: &mut Region<F>, cell: AssignedCell<F, F>) -> Result<(), Error> {
        cell.copy_advice(|| "chain_id_copy", &mut region, self.chain_id, 0)?;
        Ok(())
    }
}
