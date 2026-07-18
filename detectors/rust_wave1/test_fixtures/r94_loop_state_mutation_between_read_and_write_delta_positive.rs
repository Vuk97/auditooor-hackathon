use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Score;
#[contractimpl]
impl Score {
    // BUG: mutates is_governance=false then reads get_prior → delta wrong
    pub fn update_conviction_score(user: u64) -> u128 {
        let mut is_governance = true;
        is_governance = false;
        let _ = is_governance;
        let delta = get_prior_conviction(user);
        delta
    }
}
fn get_prior_conviction(_u: u64) -> u128 { 0 }
