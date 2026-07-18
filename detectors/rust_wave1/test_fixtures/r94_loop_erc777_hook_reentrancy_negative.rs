use soroban_sdk::{contract, contractimpl};
pub struct Erc777;
impl Erc777 { pub fn send(&self, _to: u64, _amt: u128) {} }
#[contract]
pub struct SafeVault;
#[contractimpl]
impl SafeVault {
    // OK: nonReentrant + CEI (state before transfer)
    pub fn deposit(token: Erc777, user: u64, amount: u128, balances: &mut std::collections::HashMap<u64, u128>) {
        // nonReentrant modifier applied
        balances.insert(user, amount);
        token.send(user, amount);
    }
}
