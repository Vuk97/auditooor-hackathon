use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeVault;
#[contractimpl]
impl SafeVault {
    // OK: uses mark_price for perp position valuation
    pub fn calculate_nav() -> u128 {
        let perp_position = open_position();
        let mark = mark_price();
        let _spot = oracle_price();
        perp_position * mark
    }
}
fn open_position() -> u128 { 0 }
fn mark_price() -> u128 { 0 }
fn oracle_price() -> u128 { 0 }
