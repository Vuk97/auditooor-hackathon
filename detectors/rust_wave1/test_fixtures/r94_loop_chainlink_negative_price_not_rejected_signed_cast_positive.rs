use soroban_sdk::{contract, contractimpl};
pub struct RoundData { round_id: u128, answer: i128, updated_at: u64 }
fn latest_round_data() -> RoundData { RoundData { round_id: 1, answer: -500, updated_at: 100 } }
fn block_timestamp() -> u64 { 200 }
#[contract]
pub struct PriceFeed;
#[contractimpl]
impl PriceFeed {
    // BUG: casts signed answer to u128 without rejecting negative
    pub fn current_price() -> u128 {
        let r = latest_round_data();
        let now = block_timestamp();
        assert!(now - r.updated_at < 3600, "stale");
        r.answer as u128
    }
}
