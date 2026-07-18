use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    // BUG: calls distribute_rewards with no reentrancy guard
    pub fn redeem(user: u64, amount: u128) {
        let _ = (user, amount);
        distribute_rewards(user);
    }
}
fn distribute_rewards(_u: u64) {}
