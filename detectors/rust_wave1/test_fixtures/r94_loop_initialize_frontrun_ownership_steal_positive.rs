use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Token;
#[contractimpl]
impl Token {
    // BUG: owner set from caller-supplied _owner arg with no deploy binding
    pub fn initialize(_owner: u64) {
        let mut owner = 0u64;
        owner = _owner;
        let _ = owner;
    }
}
