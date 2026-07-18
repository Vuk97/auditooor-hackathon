use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct Queue;

#[contractimpl]
impl Queue {
    pub fn configure(env: Env, admin: Address, deadline: u64, cap: u64) {
        admin.require_auth();

        let paused = Symbol::new(&env, "paused");
        let stored_deadline = Symbol::new(&env, "deadline");
        let stored_cap = Symbol::new(&env, "global_cap");

        env.storage().instance().set(&paused, &false);
        env.storage().instance().set(&stored_deadline, &deadline);
        env.storage().instance().set(&stored_cap, &cap);
    }

    pub fn unpause(env: Env, admin: Address) {
        admin.require_auth();
        let paused = Symbol::new(&env, "paused");
        env.storage().instance().set(&paused, &false);
    }

    pub fn extend_deadline(env: Env, admin: Address, next_deadline: u64) {
        admin.require_auth();
        let stored_deadline = Symbol::new(&env, "deadline");
        env.storage().instance().set(&stored_deadline, &next_deadline);
    }

    pub fn increase_cap(env: Env, admin: Address, next_cap: u64) {
        admin.require_auth();
        let stored_cap = Symbol::new(&env, "global_cap");
        env.storage().instance().set(&stored_cap, &next_cap);
    }

    pub fn process(env: Env, requested: u64, now: u64) -> Result<(), &'static str> {
        let paused = Symbol::new(&env, "paused");
        let stored_deadline = Symbol::new(&env, "deadline");
        let stored_cap = Symbol::new(&env, "global_cap");

        let is_paused: bool = env.storage().instance().get(&paused).unwrap_or(false);
        let deadline: u64 = env.storage().instance().get(&stored_deadline).unwrap_or(u64::MAX);
        let cap: u64 = env.storage().instance().get(&stored_cap).unwrap_or(u64::MAX);

        if is_paused {
            return Err("temporarily paused");
        }
        if now > deadline {
            return Err("temporarily expired");
        }
        if requested > cap {
            return Err("cap exceeded");
        }
        Ok(())
    }
}
