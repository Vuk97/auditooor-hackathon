use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct ERC4626;
#[contractimpl]
impl ERC4626 {
    // sibling deposit() exists, first-deposit = 1:1
    pub fn deposit(assets: u128) -> u128 {
        if total_supply() == 0 {
            return assets;
        }
        assets * total_supply() / total_assets()
    }

    // BUG: mint() first-deposit uses ceil_div(preview_mint) — asymmetric
    pub fn mint(shares: u128) -> u128 {
        if total_supply() == 0 {
            return ceil_div(preview_mint(shares), 1);
        }
        shares * total_assets() / total_supply()
    }
}
fn total_supply() -> u128 { 0 }
fn total_assets() -> u128 { 0 }
fn preview_mint(_s: u128) -> u128 { 0 }
fn ceil_div(_a: u128, _b: u128) -> u128 { 0 }
