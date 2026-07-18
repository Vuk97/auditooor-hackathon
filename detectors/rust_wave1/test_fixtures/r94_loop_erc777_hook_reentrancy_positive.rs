use soroban_sdk::{contract, contractimpl};
pub struct Erc777;
impl Erc777 { pub fn send(&self, _to: u64, _amt: u128) {} }
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    // BUG: erc777 .send then state mutation with no guard
    pub fn deposit(token: Erc777, user: u64, amount: u128, balances: &mut std::collections::HashMap<u64, u128>) {
        token.send(user, amount);
        balances.insert(user, amount);
    }
}
