use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafePair;
#[contractimpl]
impl SafePair {
    // OK: non_reentrant guards the buy path
    pub fn buy(token: Token, to: u64, amount: u128) {
        non_reentrant();
        token.transfer(to, amount);
        let mut reserve0 = 0u128;
        reserve0 = reserve0 + amount;
    }
}
fn non_reentrant() {}
pub struct Token;
impl Token { fn transfer(&self, _to: u64, _a: u128) {} }
