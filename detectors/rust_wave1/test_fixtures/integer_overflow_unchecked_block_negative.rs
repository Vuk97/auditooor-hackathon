use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    pub fn add(_env: Env, a: u128, b: u128) -> u128 {
        a.checked_add(b).expect("overflow")
    }
}
