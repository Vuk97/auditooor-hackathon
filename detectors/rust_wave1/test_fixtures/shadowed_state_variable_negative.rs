use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, Symbol};

const ADMIN: Symbol = symbol_short!("ADMIN");

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    pub fn read_admin(env: Env) -> Address {
        let current_admin: Address = env.storage().instance().get(&ADMIN).unwrap();
        current_admin
    }
}
