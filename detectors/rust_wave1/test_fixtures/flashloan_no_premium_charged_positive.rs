use soroban_sdk::{contract, contractimpl, Address, Env};

mod token {
    use soroban_sdk::contractclient;
    #[contractclient(name = "TokenClient")]
    pub trait T { fn transfer(&self, from: soroban_sdk::Address, to: soroban_sdk::Address, amount: i128); }
}
use token::TokenClient;

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: flash loan transfers tokens out and expects them back, no premium taken.
    pub fn flash_loan(env: Env, receiver: Address, asset: Address, amount: i128) {
        let client = TokenClient::new(&env, &asset);
        client.transfer(env.current_contract_address(), receiver.clone(), amount);
        // ... callback into receiver ...
        client.transfer(receiver, env.current_contract_address(), amount);
    }
}
