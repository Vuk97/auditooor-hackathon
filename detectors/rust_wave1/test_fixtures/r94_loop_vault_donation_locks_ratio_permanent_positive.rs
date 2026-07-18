use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    // BUG: shares = total_supply * amount / total_assets, no virtual shares
    pub fn deposit(amount: u128) -> u128 {
        let shares = total_supply() * amount / total_assets();
        shares
    }
}
fn total_supply() -> u128 { 0 }
fn total_assets() -> u128 { 0 }
