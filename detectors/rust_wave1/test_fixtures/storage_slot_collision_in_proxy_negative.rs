use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    Paused,
}

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    pub fn read_admin(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).unwrap()
    }
    pub fn set_admin(env: Env, a: Address) {
        env.storage().instance().set(&DataKey::Admin, &a);
    }
}
