use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
}

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // OK: loads the prior admin from storage using a typed Admin key,
    // calls .require_auth() on it before rotating the role.
    pub fn set_admin(env: Env, new_admin: Address) {
        let prior: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        prior.require_auth();
        env.storage().instance().set(&DataKey::Admin, &new_admin);
    }
}
