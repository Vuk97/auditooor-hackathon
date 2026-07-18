// Negative: deposit verifies the user account's mint before transferring.

use soroban_sdk::{contract, contractimpl, Env, Address};

#[contract]
pub struct SafeBridge;

#[contractimpl]
impl SafeBridge {
    pub fn deposit(env: Env, user_token_account: UserToken, expected_mint: Address, amount: u128) {
        // Check mint match BEFORE transfer
        require!(user_token_account.mint == expected_mint, "mint mismatch");
        spl_token::instruction::transfer(&user_token_account.addr, &env.pool(), amount);
    }

    pub fn deposit_v2(env: Env, user_token_account: UserToken, pool: Pool, amount: u128) {
        assert!(user_token_account.mint == pool.mint);
        token::transfer(&user_token_account.addr, &pool.addr, amount);
    }
}

pub struct UserToken { pub mint: Address, pub addr: Address }
pub struct Pool { pub mint: Address, pub addr: Address }

mod spl_token {
    pub mod instruction {
        pub fn transfer(_from: &super::Address, _to: &super::Address, _amt: u128) {}
    }
}
mod token {
    pub fn transfer(_from: &super::Address, _to: &super::Address, _amt: u128) {}
}

macro_rules! require { ($cond:expr, $msg:expr) => { if !$cond { panic!($msg); } }; }
