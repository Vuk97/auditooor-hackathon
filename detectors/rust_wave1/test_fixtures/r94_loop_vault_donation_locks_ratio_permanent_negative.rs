use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeVault;
#[contractimpl]
impl SafeVault {
    // OK: uses virtual_shares (DECIMAL_OFFSET) to prevent ratio lock
    pub fn deposit(amount: u128) -> u128 {
        let VIRTUAL_SHARES = 10u128.pow(8);
        let shares = amount * (total_supply() + VIRTUAL_SHARES) / (total_assets() + 1);
        shares
    }
}
fn total_supply() -> u128 { 0 }
fn total_assets() -> u128 { 0 }
