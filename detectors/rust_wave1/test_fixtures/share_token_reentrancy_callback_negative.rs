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
    // Effects first, then interaction.
    pub fn mint(env: Env, user: Address, asset: Address, amount: i128) {
        user.require_auth();
        let key = (Symbol::new(&env, "user_shares"), user.clone());
        env.storage().persistent().set(&key, &amount);
        let client = TokenClient::new(&env, &asset);
        client.transfer(user, env.current_contract_address(), amount);
    }
}
