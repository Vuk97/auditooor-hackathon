// Positive fixture 1: BigInteger addition without reduce.
use ark_ff::{BigInteger, BigInteger256};

fn add_field_elements(a: BigInteger256, b: BigInteger256) -> BigInteger256 {
    // Raw add on BigInteger — no .reduce() call follows.
    let mut result = a;
    result.add_nocarry(&b);
    // Missing: result.reduce() or check that result < MODULUS.
    result
}
