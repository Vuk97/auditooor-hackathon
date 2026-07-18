use soroban_sdk::{contract, contractimpl};
pub struct RoundData { round_id: u128, answer: i128, updated_at: u64 }
fn latest_round_data() -> RoundData { RoundData { round_id: 1, answer: 1000, updated_at: 100 } }
fn block_timestamp() -> u64 { 200 }
#[contract]
pub struct PriceFeed;
#[contractimpl]
impl PriceFeed {
    // SAFE: asserts answer > 0 before casting to u128
    pub fn current_price() -> u128 {
        let r = latest_round_data();
        let now = block_timestamp();
        assert!(now - r.updated_at < 3600, "stale");
        assert!(r.answer > 0, "answer must be positive");
        r.answer as u128
    }
}
