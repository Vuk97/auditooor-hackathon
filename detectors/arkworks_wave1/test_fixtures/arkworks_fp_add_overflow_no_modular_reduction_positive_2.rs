// Positive fixture 2: two BigInteger256 values added via + operator, no reduction.
use ark_ff::{BigInteger256, BigInteger};

struct Accumulator {
    inner: BigInteger256,
}

impl Accumulator {
    fn accumulate(&mut self, val: BigInteger256) {
        // self.inner = self.inner + val; — no normalization follows.
        let mut tmp = self.inner;
        tmp.add_nocarry(&val);
        self.inner = tmp;
        // Bug: if self.inner + val >= MODULUS, inner is now non-canonical.
    }
}
