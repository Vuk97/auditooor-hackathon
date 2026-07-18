use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: set_admin writes caller as the new admin, no require_auth on
    // the prior admin — any caller can seize the admin role.
    pub fn set_admin(env: Env, caller: Address) {
        let key = Symbol::new(&env, "Admin");
        env.storage().instance().set(&key, &caller);
    }
}
