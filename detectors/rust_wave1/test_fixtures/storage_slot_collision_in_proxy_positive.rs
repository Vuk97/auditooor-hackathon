use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, Symbol};

#[contracttype]
pub enum DataKey {
    Admin,
    Paused,
}

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // Reads under DataKey::Admin, writes under symbol "admin" — collision.
    pub fn read_admin(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).unwrap()
    }
    pub fn set_admin(env: Env, a: Address) {
        env.storage().instance().set(&symbol_short!("admin"), &a);
    }
}
