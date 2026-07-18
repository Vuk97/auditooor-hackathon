use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeBridge;
#[contractimpl]
impl SafeBridge {
    // OK: requires recipient bytes to be exactly 20
    pub fn transfer_token(to: Bytes, amount: u128) {
        let _ = amount;
        require(to.len() == 20);
    }
}
pub struct Bytes;
impl Bytes { fn len(&self) -> usize { 0 } }
fn require(_c: bool) {}
