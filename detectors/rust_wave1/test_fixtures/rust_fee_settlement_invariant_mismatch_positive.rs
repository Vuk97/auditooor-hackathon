use soroban_sdk::{contract, contractimpl, Address, Env};

mod token {
    use soroban_sdk::contractclient;
    #[contractclient(name = "TokenClient")]
    pub trait T {
        fn transfer(&self, from: soroban_sdk::Address, to: soroban_sdk::Address, amount: i128);
    }
}

use token::TokenClient;

#[contract]
pub struct BadFeeSettlement;

#[contractimpl]
impl BadFeeSettlement {
    pub fn pay_fee_from_receiver(env: Env, asset: Address, recipient: Address, amount: i128) {
        let client = TokenClient::new(&env, &asset);
        let protocol_fee: i128 = amount / 100;
        let treasury = env.current_contract_address();
        client.transfer(recipient.clone(), treasury, protocol_fee);
    }

    pub fn harvest_fee(token_in: u64, amount_in: u128) -> u128 {
        let platform_fee = amount_in / 10;
        router.swap(SwapParams {
            token_in,
            amount_in: platform_fee,
            amount_out_minimum: 0,
        });
        platform_fee
    }

    pub fn apply_fee_offset(user: u64, fee_pool: u128) -> u128 {
        let _ = user;
        let mut user_debt = 10_000u128;
        user_debt -= fee_pool;
        user_debt
    }
}

pub struct SwapParams {
    pub token_in: u64,
    pub amount_in: u128,
    pub amount_out_minimum: u128,
}

struct Router;

impl Router {
    fn swap(&self, _p: SwapParams) {}
}

#[allow(non_upper_case_globals)]
static router: Router = Router;
