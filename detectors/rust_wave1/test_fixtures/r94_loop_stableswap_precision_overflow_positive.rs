use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Pool;
#[contractimpl]
impl Pool {
    // BUG: Uint256 width for stableswap intermediates
    pub fn calculate_stableswap_y(x: u128, y: u128, d: u128) -> u128 {
        let sum = U256::from(x) * U256::from(y);
        (sum / U256::from(d)).as_u128()
    }

    // BUG: direct u128 * u128 on reserves
    pub fn get_d(reserve_a: u128, reserve_b: u128) -> u128 {
        let k = reserve_a * reserve_b; // overflow surface
        k / 2
    }
}
pub struct U256;
impl U256 { pub fn from(_v: u128) -> Self { Self } pub fn as_u128(self) -> u128 { 0 } }
impl std::ops::Mul for U256 { type Output = Self; fn mul(self, _: Self) -> Self { Self } }
impl std::ops::Div for U256 { type Output = Self; fn div(self, _: Self) -> Self { Self } }
