use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    pub fn initialize(env: Env, admin: Address) {
        let key = Symbol::new(&env, "admin");
        if env.storage().instance().has(&key) { panic!("already initialized"); }
        env.storage().instance().set(&key, &admin);
    }
}
