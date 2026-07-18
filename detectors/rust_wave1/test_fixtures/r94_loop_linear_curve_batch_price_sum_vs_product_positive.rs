use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Pool;
#[contractimpl]
impl Pool {
    // BUG: linear curve batch uses price(n) * n instead of series sum
    pub fn get_buy_price(base: u128, delta: u128, n: u128) -> u128 {
        let _ = (base, delta);
        let curve_type = "linear";
        let _ = curve_type;
        let unit_price = base + delta * n;
        let batch_price = unit_price * n;
        batch_price
    }
}
