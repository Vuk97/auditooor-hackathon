use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Pair;
#[contractimpl]
impl Pair {
    // BUG: transfer then update reserves, no reentrancy guard
    pub fn buy(token: Token, to: u64, amount: u128) {
        token.transfer(to, amount);
        let mut reserve0 = 0u128;
        reserve0 = reserve0 + amount;
    }
}
pub struct Token;
impl Token { fn transfer(&self, _to: u64, _a: u128) {} }
