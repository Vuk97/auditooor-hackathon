use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: single-step admin transfer, no propose/accept, no pending key
    pub fn transfer_admin(env: Env, new_admin: Address) {
        env.storage().instance().set(&Symbol::new(&env, "ADMIN"), &new_admin);
    }
}
