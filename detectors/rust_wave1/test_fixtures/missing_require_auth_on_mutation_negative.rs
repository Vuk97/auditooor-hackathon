use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    pub fn set_config(env: Env, from: Address, value: i128) {
        from.require_auth();
        env.storage().persistent().set(&Symbol::new(&env, "k"), &value);
    }
}
