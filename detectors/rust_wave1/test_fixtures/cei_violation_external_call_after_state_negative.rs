use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Vec, Val, vec};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // OK: external call BEFORE state write (correct CEI order).
    pub fn withdraw(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let token: Address = env.storage().instance().get(&Symbol::new(&env, "TOKEN")).unwrap();
        // external call first
        env.invoke_contract::<()>(
            &token,
            &Symbol::new(&env, "transfer"),
            vec![&env, user.into_val(&env), amount.into_val(&env)],
        );
        // then state write
        env.storage().persistent().set(&user, &amount);
    }

    // OK: no external call at all, just reads + writes.
    pub fn set_balance(env: Env, user: Address, amount: i128) {
        user.require_auth();
        env.storage().persistent().set(&user, &amount);
    }
}
