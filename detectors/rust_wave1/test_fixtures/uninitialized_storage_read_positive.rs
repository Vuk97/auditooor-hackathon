use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

const INIT_INDEX: i128 = 1_000_000_000_000_000_000;

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: returns INIT_INDEX when key missing; caller can't tell if set.
    pub fn get_index(env: Env, market: Address) -> i128 {
        let key = (Symbol::new(&env, "idx"), market);
        env.storage().persistent().get(&key).unwrap_or(INIT_INDEX)
    }
}
