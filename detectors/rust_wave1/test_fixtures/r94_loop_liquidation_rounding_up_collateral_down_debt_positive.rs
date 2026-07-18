use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Engine;
#[contractimpl]
impl Engine {
    // BUG: collateral seized rounded up, debt repay rounded down
    pub fn liquidate(debt: u128, collateral: u128, price: u128) -> u128 {
        let seized = ceil_div(collateral, price);
        let debt_repaid = debt * price / 1_000_000;
        let _ = debt_repaid;
        seized
    }
}
fn ceil_div(_a: u128, _b: u128) -> u128 { 0 }
