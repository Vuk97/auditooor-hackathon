use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: add_admin writes ADMINS + ADMIN_COUNT, but remove_admin only writes ADMINS.
    pub fn add_admin(env: Env, new_admin: Address) {
        env.storage().persistent().set(&Symbol::new(&env, "ADMINS"), &new_admin);
        env.storage().instance().update(&Symbol::new(&env, "ADMIN_COUNT"), |n: Option<u32>| n.unwrap_or(0) + 1);
    }

    pub fn remove_admin(env: Env, old_admin: Address) {
        env.storage().persistent().remove(&Symbol::new(&env, "ADMINS"));
        let _ = old_admin;
    }
}
