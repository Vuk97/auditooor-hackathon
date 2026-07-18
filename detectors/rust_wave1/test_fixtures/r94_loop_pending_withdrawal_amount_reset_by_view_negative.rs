use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeVault;
#[contractimpl]
impl SafeVault {
    // OK: view-only, doesn't mutate pending_withdrawal_amount
    pub fn get_total_deposited() -> u128 {
        let pending = 0u128;
        pending
    }
}
