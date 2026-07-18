use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    pub fn get_index(env: Env, market: Address) -> i128 {
        let key = (Symbol::new(&env, "idx"), market);
        if !env.storage().persistent().has(&key) {
            panic!("uninitialized");
        }
        env.storage().persistent().get(&key).unwrap()
    }
}
