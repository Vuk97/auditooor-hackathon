use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafePool;
#[contractimpl]
impl SafePool {
    // OK: uses widening_mul (U512-class helper)
    pub fn calculate_stableswap_y(x: u128, y: u128, d: u128) -> u128 {
        let sum = widening_mul(x, y);
        (sum / d as u256).as_u128()
    }

    // OK: explicit Uint512 accumulator
    pub fn get_d(reserve_a: u128, reserve_b: u128) -> u128 {
        let k: U512 = U512::from(reserve_a) * U512::from(reserve_b);
        (k / U512::from(2u128)).as_u128()
    }
}
fn widening_mul(_a: u128, _b: u128) -> U512 { U512 }
pub struct U512;
impl U512 { pub fn from(_v: u128) -> Self { Self } pub fn as_u128(self) -> u128 { 0 } }
impl std::ops::Mul for U512 { type Output = Self; fn mul(self, _: Self) -> Self { Self } }
impl std::ops::Div for U512 { type Output = Self; fn div(self, _: Self) -> Self { Self } }
type u256 = U512;
