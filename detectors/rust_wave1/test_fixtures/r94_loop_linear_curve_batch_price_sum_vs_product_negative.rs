use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafePool;
#[contractimpl]
impl SafePool {
    // OK: uses arithmetic series sum for linear curve
    pub fn get_buy_price(base: u128, delta: u128, n: u128) -> u128 {
        let curve_type = "linear";
        let _ = curve_type;
        // arithmetic_series: n * (2*base + (n+1)*delta) / 2
        let batch_price = arithmetic_series(base, delta, n);
        batch_price
    }
}
fn arithmetic_series(_b: u128, _d: u128, _n: u128) -> u128 { 0 }
