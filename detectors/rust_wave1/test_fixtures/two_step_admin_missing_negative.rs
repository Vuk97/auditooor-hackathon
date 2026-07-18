use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    pub fn propose_admin(env: Env, new_admin: Address) {
        env.storage().instance().set(&Symbol::new(&env, "PENDING_ADMIN"), &new_admin);
    }
    pub fn accept_admin(env: Env, who: Address) {
        who.require_auth();
        env.storage().instance().set(&Symbol::new(&env, "ADMIN"), &who);
    }
}
