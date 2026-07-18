use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // OK: admin is loaded from storage and require_auth() is called before
    // the pause state is written.
    pub fn pause(env: Env) {
        let akey = Symbol::new(&env, "admin");
        let admin: Address = env.storage().instance().get(&akey).unwrap();
        admin.require_auth();
        let key = Symbol::new(&env, "paused");
        env.storage().instance().set(&key, &true);
    }
}
