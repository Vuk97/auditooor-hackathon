use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // SAFE: uses saturating_sub
    pub fn accrue_rewards(env: Env) -> u64 {
        let distribution_end: u64 = 10000;
        let now: u64 = 5000;
        let remaining = distribution_end.saturating_sub(now);
        remaining
    }
}
