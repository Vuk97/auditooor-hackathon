// Positive: column `chain_id` is copy_advice'd to a fresh region but
// the chip never called meta.enable_equality(chain_id).
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem};

pub struct TxChip {
    pub tx_id: Column<Advice>,
    pub chain_id: Column<Advice>,
}

impl TxChip {
    pub fn configure<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let tx_id = meta.advice_column();
        let chain_id = meta.advice_column();
        // BUG: only tx_id is enabled for equality
        meta.enable_equality(tx_id);
        Self { tx_id, chain_id }
    }

    pub fn link<F: Field>(&self, region: &mut Region<F>, cell: AssignedCell<F, F>) -> Result<(), Error> {
        // copy chain_id from a previous region — but chain_id is not
        // equality-enabled, so the permutation argument silently skips.
        cell.copy_advice(|| "chain_id_copy", &mut region, self.chain_id, 0)?;
        Ok(())
    }
}
