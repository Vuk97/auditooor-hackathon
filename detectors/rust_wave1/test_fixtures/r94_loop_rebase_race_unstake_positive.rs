// LT contract with rebase-style token accounting
use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Lt;
#[contractimpl]
impl Lt {
    // BUG: reads balance_of without first calling _calculate_values
    pub fn unstake(balance_of: &mut std::collections::HashMap<u64, u128>, user: u64, amount: u128) {
        let bal = balance_of.get(&user).copied().unwrap_or(0);
        require(bal >= amount);
        balance_of.insert(user, bal - amount);
    }
}
// file mentions rebase context
const LT_IS_REBASE: bool = true;
fn require(_: bool) {}
