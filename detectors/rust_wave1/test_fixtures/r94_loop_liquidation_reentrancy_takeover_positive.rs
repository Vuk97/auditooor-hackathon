use soroban_sdk::{contract, contractimpl};
pub struct Token;
impl Token { pub fn transfer(&self, _to: u64, _amt: u128) {} }
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    // BUG: takeOverDebt with external call, no nonReentrant
    pub fn take_over_debt(token: Token, user: u64, amount: u128) {
        token.transfer(user, amount);
    }
}
