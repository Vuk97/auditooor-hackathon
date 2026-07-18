// Negative fixture: all `.approve(...)` calls handle the Result.

use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SafeAllowanceContract;

pub trait TokenClient {
    fn approve(&self, spender: Address, amount: i128) -> Result<(), TokenError>;
    fn increase_allowance(&self, spender: Address, amount: i128) -> Result<(), TokenError>;
}

pub enum TokenError { NotStandard }

#[contractimpl]
impl SafeAllowanceContract {
    // OK: `?` bubbles the error up
    pub fn initialize(env: Env, token: TokenImpl, htlc: Address, amount: i128)
        -> Result<(), TokenError>
    {
        token.approve(htlc.clone(), amount)?;
        Ok(())
    }

    // OK: `.unwrap()` — explicit choice to panic on failure
    pub fn bump_allowance(env: Env, token: TokenImpl, spender: Address, amount: i128) {
        token.increase_allowance(spender, amount).unwrap();
    }

    // OK: `.expect(msg)` — explicit choice with message
    pub fn dec_allowance(env: Env, token: TokenImpl, spender: Address, amount: i128) {
        token.decrease_allowance(spender, amount).expect("decrease failed");
    }

    // OK: `if let Err(e) = ...` pattern
    pub fn checked_approve(env: Env, token: TokenImpl, spender: Address, amount: i128) {
        if let Err(_e) = token.approve(spender, amount) {
            panic!("approve failed");
        }
    }

    // OK: binding + match
    pub fn matched_approve(env: Env, token: TokenImpl, spender: Address, amount: i128) {
        let r = token.approve(spender, amount);
        match r {
            Ok(()) => {}
            Err(_) => panic!("nope"),
        }
    }
}

pub struct TokenImpl;
impl TokenImpl {
    pub fn approve(&self, _s: Address, _a: i128) -> Result<(), TokenError> { Ok(()) }
    pub fn increase_allowance(&self, _s: Address, _a: i128) -> Result<(), TokenError> { Ok(()) }
    pub fn decrease_allowance(&self, _s: Address, _a: i128) -> Result<(), TokenError> { Ok(()) }
}
