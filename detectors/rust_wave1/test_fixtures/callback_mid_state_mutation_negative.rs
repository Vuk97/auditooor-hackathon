use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // OK: callback authenticates the caller before mutating.
    pub fn on_flash_loan(env: Env, initiator: Address, amount: i128) {
        initiator.require_auth();
        env.storage().persistent().set(&Symbol::new(&env, "total_debt"), &amount);
    }

    // OK: callback snapshots state first.
    pub fn receive_hook(env: Env, user: Address, delta: i128) {
        let key = Symbol::new(&env, "total_supply");
        let before: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(before + delta));
        let _ = user;
    }

    // OK: not a callback-shaped name.
    pub fn admin_set(env: Env, user: Address, amount: i128) {
        user.require_auth();
        env.storage().persistent().set(&Symbol::new(&env, "total_debt"), &amount);
    }
}
