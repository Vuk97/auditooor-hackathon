use soroban_sdk::{contract, contractimpl, Env};
#[contract]
pub struct Proposal;
#[contractimpl]
impl Proposal {
    // BUG: reversed — should be now > expiration
    pub fn is_expired(env: Env, expiration: u64) -> bool {
        env.ledger().timestamp() < expiration
    }
    // BUG: reversed — is_active should be now <= deadline
    pub fn is_active(env: Env, deadline: u64) -> bool {
        env.ledger().timestamp() > deadline
    }
}
