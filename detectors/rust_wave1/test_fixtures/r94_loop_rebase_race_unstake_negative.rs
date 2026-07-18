// LT contract with rebase — but unstake settles first
use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeLt;
#[contractimpl]
impl SafeLt {
    // OK: calls _calculate_values / _settle_balance before reading balance
    pub fn unstake(balance_of: &mut std::collections::HashMap<u64, u128>, user: u64, amount: u128) {
        _calculate_values(user);
        let bal = balance_of.get(&user).copied().unwrap_or(0);
        require(bal >= amount);
        balance_of.insert(user, bal - amount);
    }
}
const LT_IS_REBASE: bool = true;
fn _calculate_values(_u: u64) {}
fn require(_: bool) {}
