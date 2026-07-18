use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct Queue;

#[contractimpl]
impl Queue {
    pub fn configure(env: Env, caller_deadline: u64, caller_cap: u64) {
        let paused = Symbol::new(&env, "paused");
        let deadline = Symbol::new(&env, "deadline");
        let cap = Symbol::new(&env, "global_cap");

        env.storage().instance().set(&paused, &true);
        env.storage().instance().set(&deadline, &caller_deadline);
        env.storage().instance().set(&cap, &caller_cap);
    }

    pub fn process(env: Env, requested: u64, now: u64) -> Result<(), &'static str> {
        let paused = Symbol::new(&env, "paused");
        let deadline = Symbol::new(&env, "deadline");
        let cap = Symbol::new(&env, "global_cap");

        let is_paused: bool = env.storage().instance().get(&paused).unwrap_or(false);
        let stored_deadline: u64 = env.storage().instance().get(&deadline).unwrap_or(0);
        let stored_cap: u64 = env.storage().instance().get(&cap).unwrap_or(0);

        if is_paused {
            return Err("processing halted");
        }
        if now > stored_deadline {
            return Err("processing expired");
        }
        if requested > stored_cap {
            return Err("processing cap exceeded");
        }
        Ok(())
    }
}
