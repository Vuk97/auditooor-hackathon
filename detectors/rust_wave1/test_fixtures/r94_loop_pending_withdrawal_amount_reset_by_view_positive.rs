use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    // BUG: getter-style fn mutates _pending_withdrawal_amount
    pub fn get_total_deposited() -> u128 {
        let mut _pending_withdrawal_amount = 0u128;
        _pending_withdrawal_amount = 0;
        0
    }
}
