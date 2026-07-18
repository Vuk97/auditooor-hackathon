const HEARTBEAT: u64 = 3600;
use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeOracle;
#[contractimpl]
impl SafeOracle {
    // OK: heartbeat miss falls back to secondary feed
    pub fn get_price(updated_at: u64, now: u64) -> u128 {
        if now - updated_at > HEARTBEAT {
            return fallback_oracle();
        }
        100
    }
}
fn fallback_oracle() -> u128 { 100 }
