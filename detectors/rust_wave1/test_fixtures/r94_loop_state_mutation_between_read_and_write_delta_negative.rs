use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeScore;
#[contractimpl]
impl SafeScore {
    // OK: reads prior conviction FIRST, mutates afterwards
    pub fn update_conviction_score(user: u64) -> u128 {
        let delta = get_prior_conviction(user);
        let mut is_governance = true;
        is_governance = false;
        let _ = is_governance;
        delta
    }
}
fn get_prior_conviction(_u: u64) -> u128 { 0 }
