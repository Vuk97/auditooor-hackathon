use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: wrapping_add on user value — silently overflows.
    pub fn add(_env: Env, a: u128, b: u128) -> u128 {
        a.wrapping_add(b)
    }
}
