use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    pub fn do_it(_env: Env, x: i128) -> i128 {
        if x > 0 {
            return x * 2;
        }
        let y = x + 1;
        y
    }
}
