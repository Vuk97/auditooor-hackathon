use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeBridge;
#[contractimpl]
impl SafeBridge {
    // OK: non_reentrant guard wraps the balance-diff measurement
    pub fn receive_token(token: u64, amount: u128) -> u128 {
        non_reentrant();
        let balance_before = balance_of(vault());
        token_receive(token, amount);
        let received = balance_of(vault()) - balance_before;
        received
    }
}
fn non_reentrant() {}
fn token_receive(_t: u64, _a: u128) {}
fn balance_of(_v: u64) -> u128 { 0 }
fn vault() -> u64 { 0 }
