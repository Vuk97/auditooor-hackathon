use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Pool;
#[contractimpl]
impl Pool {
    // BUG: bare transfer call, return value ignored
    pub fn deposit(token: &Token, user: u64, amount: u128) {
        token.transfer(user, amount);
    }
}
pub struct Token;
impl Token { pub fn transfer(&self, _to: u64, _amt: u128) -> bool { true } }
