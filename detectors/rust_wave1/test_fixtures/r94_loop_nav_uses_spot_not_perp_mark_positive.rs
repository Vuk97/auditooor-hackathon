use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    // BUG: NAV marks perp position to spot oracle price
    pub fn calculate_nav() -> u128 {
        let perp_position = open_position();
        let price = oracle_price();
        perp_position * price
    }
}
fn open_position() -> u128 { 0 }
fn oracle_price() -> u128 { 0 }
