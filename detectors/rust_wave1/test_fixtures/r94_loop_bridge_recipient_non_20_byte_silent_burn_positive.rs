use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Bridge;
#[contractimpl]
impl Bridge {
    // BUG: validates only min/max length, not exactly 20 bytes
    pub fn transfer_token(to: Bytes, amount: u128) {
        let _ = amount;
        validate_length_non_empty(&to);
    }
}
pub struct Bytes;
fn validate_length_non_empty(_b: &Bytes) {}
