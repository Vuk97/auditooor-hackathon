// Negative fixture: the first limb sum is constrained to 65 bits before
// deriving c1, preserving the carry bit.
use ark_r1cs_std::{fields::fp::FpVar, uint64::UInt64, boolean::Boolean};

struct Error;

fn bit_constrain(_raw: FpVar, _bits: usize) -> Result<Vec<Boolean>, Error> {
    Ok(Vec::new())
}

fn le_bits_to_fp_var(_bits: &[Boolean]) -> FpVar {
    unimplemented!()
}

fn add(sum_raw: FpVar) -> Result<(UInt64, FpVar), Error> {
    // OK: 65 bits are constrained, so sum_bits[64..] contains the carry.
    let sum_bits = bit_constrain(sum_raw, 65)?;
    let low_limb = UInt64::from_bits_le(&sum_bits[0..64]);
    let c1 = le_bits_to_fp_var(&sum_bits[64..]);

    Ok((low_limb, c1))
}
