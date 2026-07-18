use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Quest;
#[contractimpl]
impl Quest {
    // BUG: transfers fee but never flags it as withdrawn — replay drain
    pub fn withdraw_fee(token: Token, to: u64, amount: u128) {
        token.transfer(to, amount);
    }
}
pub struct Token;
impl Token { pub fn transfer(&self, _to: u64, _amt: u128) {} }
