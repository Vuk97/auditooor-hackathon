use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, Symbol, Vec, Val, vec};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // Local function — declares 2 args (after env).
    pub fn transfer(env: Env, to: Address, amount: i128) {
        let _ = (to, amount);
        let _ = env;
    }

    // VULN A: stringly-typed call passes 3 args to same-crate `transfer`
    // which declares 2.
    pub fn do_bad_call(env: Env, target: Address, a: Address, b: i128, c: i128) -> Val {
        env.invoke_contract(&target, &Symbol::new(&env, "transfer"), vec![&env, a.into_val(&env), b.into_val(&env), c.into_val(&env)])
    }

    // VULN B: typo — "transer" is 1 edit from sdk method `transfer`.
    pub fn do_typo_call(env: Env, target: Address, args: Vec<Val>) -> Val {
        env.invoke_contract(&target, &symbol_short!("transer"), args)
    }
}
