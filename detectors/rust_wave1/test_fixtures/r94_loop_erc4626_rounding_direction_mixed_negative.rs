use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeVault;
#[contractimpl]
impl SafeVault {
    // OK: both convert and preview_deposit floor (no direction gap)
    pub fn convert_to_shares(assets: u128) -> u128 {
        assets * total_supply() / total_assets()
    }
    pub fn preview_deposit(assets: u128) -> u128 {
        assets * total_supply() / total_assets()
    }
}
fn total_supply() -> u128 { 1 }
fn total_assets() -> u128 { 1 }
