use soroban_sdk::{contract, contractimpl};
pub struct RoundData { round_id: u128, answer: i128, updated_at: u64 }
fn latest_round_data() -> RoundData { RoundData { round_id: 1, answer: 1_000, updated_at: 0 } }
fn block_timestamp() -> u64 { 100 }
const STALENESS_WINDOW: u64 = 3600;
#[contract]
pub struct PriceFeed;
#[contractimpl]
impl PriceFeed {
    // SAFE: rejects feeds older than STALENESS_WINDOW
    pub fn current_price() -> u128 {
        let r = latest_round_data();
        let now = block_timestamp();
        assert!(now - r.updated_at < STALENESS_WINDOW, "feed stale");
        r.answer as u128
    }
}
