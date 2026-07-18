use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    pub fn debt(env: Env) -> i128 {
        // VULN: unwrap_or(0) on persistent().get → TTL archival masks state
        env.storage().persistent().get::<_, i128>(&1u32).unwrap_or(0)
    }
    pub fn debt2(env: Env) -> i128 {
        env.storage().instance().get::<_, i128>(&2u32).unwrap_or(0i128)
    }
}
