use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafePerp;
#[contractimpl]
impl SafePerp {
    // OK: uses perp_price (mark) for valuation
    pub fn position_value(size: u128) -> u128 {
        let p = perp_price();
        let _underlying_price = underlying_price();
        size * p
    }
}
fn perp_price() -> u128 { 0 }
fn underlying_price() -> u128 { 0 }
