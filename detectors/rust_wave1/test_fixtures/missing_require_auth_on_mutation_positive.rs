use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: mutates persistent storage, no require_auth
    pub fn set_config(env: Env, from: Address, value: i128) {
        env.storage().persistent().set(&Symbol::new(&env, "k"), &value);
    }
}
