use soroban_sdk::{contract, contractimpl, Address, Env};

mod token {
    use soroban_sdk::contractclient;
    #[contractclient(name = "TokenClient")]
    pub trait T {
        fn transfer(&self, from: soroban_sdk::Address, to: soroban_sdk::Address, amount: i128);
    }
}
use token::TokenClient;

mod receiver {
    use soroban_sdk::contractclient;
    #[contractclient(name = "ReceiverClient")]
    pub trait T {
        fn execute_operation(&self, asset: soroban_sdk::Address, amount: i128);
    }
}
use receiver::ReceiverClient;

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // SAFE: no state mutations between callback and verify
    pub fn flash_loan(env: Env, receiver: Address, asset: Address, amount: i128) {
        let client = TokenClient::new(&env, &asset);
        client.transfer(env.current_contract_address(), receiver.clone(), amount);
        let r = ReceiverClient::new(&env, &receiver);
        r.execute_operation(asset.clone(), amount);
        verify_repayment(&env, &asset, amount);
    }
}

fn verify_repayment(_: &Env, _: &Address, _: i128) {}
