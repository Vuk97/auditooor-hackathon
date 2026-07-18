const MAX_EXPIRATION: u64 = 365 * 24 * 60 * 60;
use soroban_sdk::{contract, contractimpl};
pub struct Name { pub expiration: u64 }
#[contract]
pub struct Registry;
#[contractimpl]
impl Registry {
    // BUG: validates delta <= MAX, then adds delta to field, no sum-check
    pub fn extend_expiration(name: &mut Name, duration: u64) {
        require(duration <= MAX_EXPIRATION);
        name.expiration += duration;
    }
}
fn require(_: bool) {}
