use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    // BUG: convert_to_shares floors, preview_deposit ceils → gap
    pub fn convert_to_shares(assets: u128) -> u128 {
        assets * total_supply() / total_assets()
    }
    pub fn preview_deposit(assets: u128) -> u128 {
        ceil_div(assets * total_supply(), total_assets())
    }
}
fn total_supply() -> u128 { 1 }
fn total_assets() -> u128 { 1 }
fn ceil_div(_a: u128, _b: u128) -> u128 { 0 }
