const HEARTBEAT: u64 = 3600;
use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Oracle;
#[contractimpl]
impl Oracle {
    // BUG: reverts on stale with no fallback feed
    pub fn get_price(updated_at: u64, now: u64) -> u128 {
        require(now - updated_at <= HEARTBEAT);
        100
    }
}
fn require(_: bool) {}
