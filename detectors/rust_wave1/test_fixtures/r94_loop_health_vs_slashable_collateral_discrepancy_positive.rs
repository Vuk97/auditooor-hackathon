use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Agent;
#[contractimpl]
impl Agent {
    // health computed from weighted_collateral
    pub fn compute_health(user: u64) -> u128 {
        let wc = weighted_collateral(user);
        wc * 100
    }

    // BUG: slashable uses raw_collateral (different model)
    pub fn slashable_collateral(user: u64) -> u128 {
        let raw = raw_collateral(user);
        raw
    }
}
fn weighted_collateral(_u: u64) -> u128 { 0 }
fn raw_collateral(_u: u64) -> u128 { 0 }
