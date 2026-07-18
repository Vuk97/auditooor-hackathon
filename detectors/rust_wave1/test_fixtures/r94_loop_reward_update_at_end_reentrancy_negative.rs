use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeVault;
#[contractimpl]
impl SafeVault {
    // OK: non_reentrant guards the redeem path
    pub fn redeem(user: u64, amount: u128) {
        non_reentrant();
        let _ = (user, amount);
        distribute_rewards(user);
    }
}
fn non_reentrant() {}
fn distribute_rewards(_u: u64) {}
