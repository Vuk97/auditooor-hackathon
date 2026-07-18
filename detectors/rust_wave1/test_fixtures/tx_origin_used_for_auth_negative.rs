use soroban_sdk::{contract, contractimpl, Address, Env};

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
    pub fn move_funds(env: Env, payer: Address, recipient: Address, asset: Address, amount: i128) {
        payer.require_auth();
        let client = TokenClient::new(&env, &asset);
        client.transfer(payer, recipient, amount);
    }
}
