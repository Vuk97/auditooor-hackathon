use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

mod token {
    use soroban_sdk::contractclient;
    #[contractclient(name = "TokenClient")]
    pub trait T { fn transfer(&self, from: soroban_sdk::Address, to: soroban_sdk::Address, amount: i128); }
}
use token::TokenClient;

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    pub fn withdraw(env: Env, user: Address, asset: Address, amount: i128) {
        user.require_auth();
        let key = (Symbol::new(&env, "collateral"), user.clone());
        let prev: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(prev - amount));
        let client = TokenClient::new(&env, &asset);
        client.transfer(env.current_contract_address(), user, amount);
    }
}
