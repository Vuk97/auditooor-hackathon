use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Vec, Val, vec};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: write storage, THEN make external call — classic CEI violation.
    pub fn withdraw(env: Env, user: Address, amount: i128) {
        user.require_auth();
        // state write
        env.storage().persistent().set(&user, &amount);
        // external call AFTER the write — exposed to reentrancy
        let token: Address = env.storage().instance().get(&Symbol::new(&env, "TOKEN")).unwrap();
        env.invoke_contract::<()>(
            &token,
            &Symbol::new(&env, "transfer"),
            vec![&env, user.into_val(&env), amount.into_val(&env)],
        );
    }
}
