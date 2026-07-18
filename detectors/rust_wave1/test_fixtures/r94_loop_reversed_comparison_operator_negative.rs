use soroban_sdk::{contract, contractimpl, Env};
#[contract]
pub struct SafeProposal;
#[contractimpl]
impl SafeProposal {
    // OK: now >= expiration is "expired"
    pub fn is_expired(env: Env, expiration: u64) -> bool {
        env.ledger().timestamp() >= expiration
    }
    // OK: now < deadline is "active"
    pub fn is_active(env: Env, deadline: u64) -> bool {
        env.ledger().timestamp() < deadline
    }
}
