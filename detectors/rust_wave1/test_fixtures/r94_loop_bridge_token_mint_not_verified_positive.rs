// Positive: deposit transfers from user token-account without mint check.

use soroban_sdk::{contract, contractimpl, Env, Address};

#[contract]
pub struct Bridge;

#[contractimpl]
impl Bridge {
    pub fn deposit(env: Env, user_token_account: Address, amount: u128) {
        // BUG: no check that user_token_account.mint == expected_mint
        spl_token::instruction::transfer(&user_token_account, &env.pool(), amount);
    }
}

mod spl_token {
    pub mod instruction {
        pub fn transfer(_from: &super::Address, _to: &super::Address, _amt: u128) {}
    }
}
