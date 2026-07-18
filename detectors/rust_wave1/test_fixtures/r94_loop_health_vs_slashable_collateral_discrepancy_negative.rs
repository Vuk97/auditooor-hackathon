use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeAgent;
#[contractimpl]
impl SafeAgent {
    // Both use weighted_collateral — consistent model
    pub fn compute_health(user: u64) -> u128 {
        let wc = weighted_collateral(user);
        wc * 100
    }

    pub fn slashable_collateral(user: u64) -> u128 {
        let wc = weighted_collateral(user);
        wc
    }
}
fn weighted_collateral(_u: u64) -> u128 { 0 }
