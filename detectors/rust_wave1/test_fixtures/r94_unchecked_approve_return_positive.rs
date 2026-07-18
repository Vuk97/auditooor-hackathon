// Positive fixture: calls `.approve(...)` and drops the Result.
// Based on Solodit #64933 (Garden / UDA.sol Rust analogue).

use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct UniqueDepositAddress;

pub trait TokenClient {
    fn approve(&self, spender: Address, amount: i128) -> Result<(), TokenError>;
    fn increase_allowance(&self, spender: Address, amount: i128) -> Result<(), TokenError>;
}

pub enum TokenError { NotStandard }

#[contractimpl]
impl UniqueDepositAddress {
    pub fn initialize(env: Env, token: TokenImpl, htlc: Address, amount: i128) {
        // BUG 1: explicit `let _ = ` drops the Result
        let _ = token.approve(htlc.clone(), amount);
    }

    pub fn bump_allowance(env: Env, token: TokenImpl, spender: Address, amount: i128) {
        // BUG 2: expression-statement with no handling — approve fires-and-forgets
        token.increase_allowance(spender, amount);
    }

    pub fn dec_allowance(env: Env, token: TokenImpl, spender: Address, amount: i128) {
        // BUG 3: decrease_allowance also dropped
        token.decrease_allowance(spender, amount);
    }
}

pub struct TokenImpl;
impl TokenImpl {
    pub fn approve(&self, _s: Address, _a: i128) -> Result<(), TokenError> { Ok(()) }
    pub fn increase_allowance(&self, _s: Address, _a: i128) -> Result<(), TokenError> { Ok(()) }
    pub fn decrease_allowance(&self, _s: Address, _a: i128) -> Result<(), TokenError> { Ok(()) }
}
