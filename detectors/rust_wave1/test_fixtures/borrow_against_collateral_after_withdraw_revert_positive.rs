use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, IntoVal, Val, Vec};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: try_invoke + .ok(), then debits collateral regardless of success.
    pub fn withdraw(env: Env, user: Address, asset: Address, amount: i128) {
        user.require_auth();
        let method = Symbol::new(&env, "transfer_from");
        let mut args: Vec<Val> = Vec::new(&env);
        args.push_back(user.to_val());
        args.push_back(amount.into_val(&env));
        let _ = env.try_invoke_contract::<Val, soroban_sdk::Error>(&asset, &method, args).ok();
        let key = (Symbol::new(&env, "collateral"), user.clone());
        let prev: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(prev - amount));
    }
}
