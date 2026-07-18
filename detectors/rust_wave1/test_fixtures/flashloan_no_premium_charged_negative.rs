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
    pub fn flash_loan(env: Env, receiver: Address, asset: Address, amount: i128) {
        let client = TokenClient::new(&env, &asset);
        let premium: i128 = amount / 1000;
        client.transfer(env.current_contract_address(), receiver.clone(), amount);
        client.transfer(receiver, env.current_contract_address(), amount + premium);
    }
}
