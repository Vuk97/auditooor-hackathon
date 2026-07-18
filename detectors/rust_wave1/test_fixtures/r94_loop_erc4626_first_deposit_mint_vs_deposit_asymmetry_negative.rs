use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeERC4626;
#[contractimpl]
impl SafeERC4626 {
    // OK: deposit and mint share the same first-deposit convention
    pub fn deposit(assets: u128) -> u128 {
        if total_supply() == 0 {
            return assets;
        }
        assets * total_supply() / total_assets()
    }

    pub fn mint(shares: u128) -> u128 {
        if total_supply() == 0 {
            return shares;
        }
        shares * total_assets() / total_supply()
    }
}
fn total_supply() -> u128 { 0 }
fn total_assets() -> u128 { 0 }
