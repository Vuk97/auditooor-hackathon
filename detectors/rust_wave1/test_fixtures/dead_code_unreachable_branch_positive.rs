use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    pub fn do_it(_env: Env, x: i128) -> i128 {
        if false {
            return x * 2;
        }
        panic!("unreachable");
        let _dead = x + 1;
        x
    }
}
