use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: permissionless init, no already-initialized guard, no auth.
    pub fn initialize(env: Env, admin: Address) {
        env.storage().instance().set(&Symbol::new(&env, "admin"), &admin);
    }
}
