// Positive #2: nonce column copy-advice'd without enable_equality.
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem};

pub struct AccountChip {
    pub address: Column<Advice>,
    pub nonce: Column<Advice>,
}

impl AccountChip {
    pub fn configure<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let address = meta.advice_column();
        let nonce = meta.advice_column();
        meta.enable_equality(address); // BUG: nonce not enabled
        Self { address, nonce }
    }

    pub fn copy_nonce<F: Field>(&self, region: &mut Region<F>, cell: AssignedCell<F, F>) -> Result<(), Error> {
        cell.copy_advice(|| "nonce_dup", &mut region, self.nonce, 1)?;
        Ok(())
    }
}
