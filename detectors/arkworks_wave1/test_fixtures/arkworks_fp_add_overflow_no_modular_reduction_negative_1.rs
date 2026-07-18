// Negative fixture 1: BigInteger addition followed by reduce — no finding.
use ark_ff::{BigInteger256, BigInteger};

fn safe_add(a: BigInteger256, b: BigInteger256, modulus: &BigInteger256) -> BigInteger256 {
    let mut result = a;
    result.add_nocarry(&b);
    // Proper modular reduction applied.
    if &result >= modulus {
        result.sub_noborrow(modulus);
    }
    result
}
