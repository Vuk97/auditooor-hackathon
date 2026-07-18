// Positive fixture 1: `secret` allocated but never enforced.
use bellperson::{ConstraintSystem, SynthesisError};
use bellperson::gadgets::num::AllocatedNum;
use bls12_381::Scalar;

struct MyCircuit {
    pub secret: Option<Scalar>,
    pub public_val: Option<Scalar>,
}

impl<CS: ConstraintSystem<Scalar>> bellperson::Circuit<Scalar> for MyCircuit {
    fn synthesize(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // `secret` is allocated but never constrained.
        let secret = AllocatedNum::alloc(cs.namespace(|| "secret"), || {
            self.secret.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // `public_val` is properly constrained.
        let public_val = AllocatedNum::alloc(cs.namespace(|| "public_val"), || {
            self.public_val.ok_or(SynthesisError::AssignmentMissing)
        })?;
        public_val.inputize(cs.namespace(|| "public_val_input"))?;
        cs.enforce(
            || "public_val squared",
            |lc| lc + public_val.get_variable(),
            |lc| lc + public_val.get_variable(),
            |lc| lc + public_val.get_variable(),
        );
        Ok(())
    }
}
