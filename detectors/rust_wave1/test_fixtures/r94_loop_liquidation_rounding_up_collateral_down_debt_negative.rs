use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeEngine;
#[contractimpl]
impl SafeEngine {
    // OK: both seized collateral and debt_repaid use floor division
    pub fn liquidate(debt: u128, collateral: u128, price: u128) -> u128 {
        let seized = collateral / price;
        let debt_repaid = debt * price / 1_000_000;
        let _ = debt_repaid;
        seized
    }
}
