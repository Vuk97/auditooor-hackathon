use soroban_sdk::{contract, contractimpl};

const MODULUS: u128 = 218882428718392752222464057452572750885;

#[contract]
pub struct Verifier;

#[contractimpl]
impl Verifier {
    pub fn verify_nonzero_witness(x: FieldElem) -> bool {
        let inv = mod_inverse(x);
        x.mul(inv).is_one()
    }
}

pub fn mod_inverse(x: FieldElem) -> FieldElem {
    // BUG: Fermat inverse silently maps zero to zero instead of rejecting it.
    x.pow_mod(MODULUS - 2, MODULUS)
}

pub struct FieldElem(pub u128);

impl FieldElem {
    pub fn pow_mod(self, _exp: u128, _modulus: u128) -> FieldElem {
        self
    }

    pub fn mul(self, _rhs: FieldElem) -> FieldElem {
        self
    }

    pub fn is_one(&self) -> bool {
        self.0 == 1
    }
}
