use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: set_admin stores `new_admin` directly without checking zero.
    pub fn set_admin(env: Env, new_admin: Address) {
        env.storage().instance().set(&Symbol::new(&env, "admin"), &new_admin);
    }

    // VULN: initialize stores multiple address params, none checked.
    pub fn initialize(env: Env, oracle: Address, treasury: Address) {
        env.storage().instance().set(&Symbol::new(&env, "oracle"), &oracle);
        env.storage().instance().set(&Symbol::new(&env, "treasury"), &treasury);
    }
}
