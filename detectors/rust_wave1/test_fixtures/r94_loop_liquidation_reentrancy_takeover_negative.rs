use soroban_sdk::{contract, contractimpl};
pub struct Token;
impl Token { pub fn transfer(&self, _to: u64, _amt: u128) {} }
#[contract]
pub struct SafeVault;
#[contractimpl]
impl SafeVault {
    // OK: non_reentrant guard call
    pub fn take_over_debt(token: Token, user: u64, amount: u128) {
        non_reentrant();
        token.transfer(user, amount);
    }
}
fn non_reentrant() {}
