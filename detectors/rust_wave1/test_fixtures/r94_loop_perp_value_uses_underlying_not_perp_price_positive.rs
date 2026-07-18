use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Perp;
#[contractimpl]
impl Perp {
    // BUG: uses underlying_price instead of perp_price for valuation
    pub fn position_value(size: u128) -> u128 {
        let p = underlying_price();
        size * p
    }
}
fn underlying_price() -> u128 { 0 }
