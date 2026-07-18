use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafePool;
#[contractimpl]
impl SafePool {
    // OK: uses safeTransfer (require-wrapped)
    pub fn deposit(token: &Token, user: u64, amount: u128) {
        token.safe_transfer(user, amount);
    }
}
pub struct Token;
impl Token {
    pub fn safe_transfer(&self, _to: u64, _amt: u128) {}
    pub fn transfer(&self, _to: u64, _amt: u128) -> bool { true }
}
