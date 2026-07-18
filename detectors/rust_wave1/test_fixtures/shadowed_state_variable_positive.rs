use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, Symbol};

const ADMIN: Symbol = symbol_short!("ADMIN");

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: local `admin` shadows the module const ADMIN.
    pub fn read_admin(env: Env) -> Address {
        let admin: Address = env.storage().instance().get(&ADMIN).unwrap();
        admin
    }
}
