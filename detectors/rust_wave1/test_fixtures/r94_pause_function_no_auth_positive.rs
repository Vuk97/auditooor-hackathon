use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: pause() toggles a global flag in storage — no require_auth,
    // no admin-gate helper — anyone can halt the protocol.
    pub fn pause(env: Env) {
        let key = Symbol::new(&env, "paused");
        env.storage().instance().set(&key, &true);
    }
}
