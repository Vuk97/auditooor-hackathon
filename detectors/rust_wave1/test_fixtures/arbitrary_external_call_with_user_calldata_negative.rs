use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Vec, Val};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // Target comes from storage (admin-set), only amount is user-controlled
    pub fn deposit(env: Env, from: Address, amount: i128) {
        from.require_auth();
        let token: Address = env.storage().instance().get(&Symbol::new(&env, "tok")).unwrap();
        let sym = Symbol::new(&env, "transfer");
        let mut args: Vec<Val> = Vec::new(&env);
        args.push_back(from.to_val());
        args.push_back(amount.into());
        let _r: Val = env.invoke_contract(&token, &sym, args);
    }
}
