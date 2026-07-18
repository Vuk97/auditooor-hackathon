use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Pool;
#[contractimpl]
impl Pool {
    // BUG: pmm price from reserves, no external sanity
    pub fn query(base_balance: u128, quote_balance: u128) -> u128 {
        quote_balance * 1_000_000 / base_balance
    }
}
