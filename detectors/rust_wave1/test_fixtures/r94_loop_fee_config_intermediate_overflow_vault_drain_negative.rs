use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeLibrary;
#[contractimpl]
impl SafeLibrary {
    // OK: uses mul_div (FullMath) to avoid intermediate overflow
    pub fn pnl(position: u128, price: u128, fee_bps: u128) -> u128 {
        let step = mul_div(position, price, 1_000_000_000_000_000_000u128);
        mul_div(step, fee_bps, 1_000_000_000_000_000_000u128)
    }
}
fn mul_div(_a: u128, _b: u128, _d: u128) -> u128 { 0 }
