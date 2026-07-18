use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: raw `-` between distribution_end and now
    pub fn accrue_rewards(env: Env) -> u64 {
        let distribution_end: u64 = 10000;
        let now: u64 = 5000;
        let remaining = distribution_end - now;
        remaining
    }
}
