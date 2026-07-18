use soroban_sdk::{contract, contractimpl};

pub struct RoundData {
    round_id: u128,
    answer: i128,
    updated_at: u64,
}

fn latest_round_data() -> RoundData {
    RoundData {
        round_id: 1,
        answer: -500,
        updated_at: 100,
    }
}

fn block_timestamp() -> u64 {
    200
}

#[contract]
pub struct PriceFeed;

#[contractimpl]
impl PriceFeed {
    // CLEAN: the function reads the feed, but only casts an unrelated scalar.
    pub fn current_price() -> u128 {
        let r = latest_round_data();
        let now = block_timestamp();
        assert!(now - r.updated_at < 3600, "stale");
        let scale = now as u128;
        let _unused = r.round_id;
        scale + 1
    }
}
