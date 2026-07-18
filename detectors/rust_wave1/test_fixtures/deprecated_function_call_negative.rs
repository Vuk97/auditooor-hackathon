use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    pub fn new_price(_env: Env) -> i128 { 42 }
    pub fn caller(env: Env) -> i128 {
        Self::new_price(env)
    }
}
