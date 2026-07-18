use soroban_sdk::{contract, contractimpl};
pub struct RoundData { round_id: u128, answer: i128, updated_at: u64 }
fn latest_round_data() -> RoundData { RoundData { round_id: 1, answer: 1_000, updated_at: 0 } }
#[contract]
pub struct PriceFeed;
#[contractimpl]
impl PriceFeed {
    // BUG: uses latest_round_data().answer without checking updated_at
    pub fn current_price() -> u128 {
        let r = latest_round_data();
        r.answer as u128
    }
}
