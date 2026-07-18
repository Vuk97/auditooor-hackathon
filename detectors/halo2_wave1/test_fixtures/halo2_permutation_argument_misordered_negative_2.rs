// Negative #2: copy_advice uses an instance column (auto eq-enabled).
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Instance};

pub struct InstanceChip {
    pub instance: Column<Instance>,
}

impl InstanceChip {
    pub fn configure<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let instance = meta.instance_column();
        Self { instance }
    }

    pub fn link<F: Field>(&self, region: &mut Region<F>, cell: AssignedCell<F, F>) -> Result<(), Error> {
        cell.copy_advice(|| "to_instance", &mut region, self.instance, 0)?;
        Ok(())
    }
}
