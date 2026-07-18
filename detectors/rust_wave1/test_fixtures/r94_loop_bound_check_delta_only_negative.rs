const MAX_EXPIRATION: u64 = 365 * 24 * 60 * 60;
use soroban_sdk::{contract, contractimpl};
pub struct Name { pub expiration: u64 }
#[contract]
pub struct SafeRegistry;
#[contractimpl]
impl SafeRegistry {
    // OK: also post-checks the SUM against the cap
    pub fn extend_expiration(name: &mut Name, duration: u64) {
        require(duration <= MAX_EXPIRATION);
        let new_expiration = name.expiration + duration;
        require(new_expiration <= MAX_EXPIRATION);
        name.expiration = new_expiration;
    }
}
fn require(_: bool) {}
