use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // OK: add_admin and remove_admin touch the same two keys.
    pub fn add_admin(env: Env, new_admin: Address) {
        env.storage().persistent().set(&Symbol::new(&env, "ADMINS"), &new_admin);
        env.storage().instance().set(&Symbol::new(&env, "ADMIN_COUNT"), &1u32);
    }

    pub fn remove_admin(env: Env, old_admin: Address) {
        env.storage().persistent().remove(&Symbol::new(&env, "ADMINS"));
        env.storage().instance().set(&Symbol::new(&env, "ADMIN_COUNT"), &0u32);
        let _ = old_admin;
    }

    // OK: unpaired — only add_operator exists, no flag expected.
    pub fn add_operator(env: Env, op: Address) {
        env.storage().persistent().set(&Symbol::new(&env, "OP"), &op);
    }

    // OK: different stems — add_admin must NOT pair with remove_operator.
    pub fn remove_operator(env: Env, op: Address) {
        env.storage().persistent().remove(&Symbol::new(&env, "OP"));
        let _ = op;
    }
}
