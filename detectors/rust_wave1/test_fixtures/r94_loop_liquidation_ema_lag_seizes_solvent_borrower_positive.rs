use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Engine;
#[contractimpl]
impl Engine {
    // BUG: reads ema_price only, no spot cross-check
    pub fn is_liquidatable(collateral: u128, debt: u128) -> bool {
        let ema = ema_price();
        let value = collateral * ema / 1_000_000;
        value < debt
    }
}
fn ema_price() -> u128 { 0 }
