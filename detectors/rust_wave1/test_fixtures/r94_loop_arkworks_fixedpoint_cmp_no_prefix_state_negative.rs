use std::iter::zip;

struct Fq;
struct SynthesisError;
struct Boolean<T>(T);

impl<T> Boolean<T> {
    fn constant(_value: bool) -> Self {
        todo!()
    }

    fn not(&self) -> Self {
        todo!()
    }

    fn or(&self, _other: &Self) -> Result<Self, SynthesisError> {
        todo!()
    }

    fn and(&self, _other: &Self) -> Result<Self, SynthesisError> {
        todo!()
    }

    fn enforce_equal(&self, _other: &Self) -> Result<(), SynthesisError> {
        todo!()
    }
}

struct U128x128Var {
    bits: Vec<Boolean<Fq>>,
}

impl U128x128Var {
    fn to_bits_le(&self) -> Vec<Boolean<Fq>> {
        todo!()
    }

    pub fn enforce_cmp(&self, other: &U128x128Var) -> Result<(), SynthesisError> {
        let self_bits: Vec<Boolean<Fq>> = self.to_bits_le().into_iter().rev().collect();
        let other_bits: Vec<Boolean<Fq>> = other.to_bits_le().into_iter().rev().collect();

        let mut gt = Boolean::constant(false);
        let mut lt = Boolean::constant(false);
        for (self_bit, other_bit) in zip(self_bits, other_bits) {
            let decided = gt.or(&lt)?;
            let undecided = decided.not();
            let self_gt = self_bit.and(&other_bit.not())?;
            let self_lt = self_bit.not().and(&other_bit)?;
            gt = gt.or(&undecided.and(&self_gt)?)?;
            lt = lt.or(&undecided.and(&self_lt)?)?;
        }

        lt.enforce_equal(&Boolean::constant(true))?;
        Ok(())
    }
}
