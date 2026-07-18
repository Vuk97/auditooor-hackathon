// Positive fixture 2: `mask_bit` allocated via alloc_input, never enforced.
use bellperson::{ConstraintSystem, SynthesisError, Variable};

struct MaskCircuit {
    pub mask_bit: Option<bool>,
}

fn synthesize<CS: ConstraintSystem<bellperson::bls12_381::Scalar>>(
    self_: MaskCircuit,
    cs: &mut CS,
) -> Result<(), SynthesisError> {
    // mask_bit is allocated as input but no cs.enforce uses it.
    let mask_bit = cs.alloc_input(
        || "mask_bit",
        || {
            self_.mask_bit
                .map(|b| if b { bellperson::bls12_381::Scalar::one() } else { bellperson::bls12_381::Scalar::zero() })
                .ok_or(SynthesisError::AssignmentMissing)
        },
    )?;
    // No cs.enforce referencing mask_bit.
    Ok(())
}
