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
    // VULN: fee deducted FROM recipient — wrong party pays the fee.
    pub fn pay_out(env: Env, asset: Address, recipient: Address, amount: i128) {
        let client = TokenClient::new(&env, &asset);
        let fee: i128 = amount * 10 / 1000;
        let treasury = env.current_contract_address();
        client.transfer(recipient.clone(), treasury, fee);
        client.transfer(env.current_contract_address(), recipient, amount - fee);
    }
}
