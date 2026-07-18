use soroban_sdk::{contract, contractimpl};

pub struct RoundData {
    pub answer: i128,
    pub updated_at: u64,
}

pub struct PriceFeed {
    pub conf: u64,
}

fn latest_round_data() -> RoundData {
    RoundData { answer: 500, updated_at: 100 }
}

fn block_timestamp() -> u64 {
    200
}

#[contract]
pub struct SafeOracleAdapter;

#[contractimpl]
impl SafeOracleAdapter {
    pub fn current_price() -> u128 {
        let r = latest_round_data();
        let now = block_timestamp();
        assert!(now - r.updated_at < 3600, "stale");
        assert!(r.answer > 0, "answer must be positive");
        r.answer as u128
    }

    pub fn update_index(new_price: i128, current_index: i128, price_feed: PriceFeed) -> bool {
        let delta = (new_price - current_index).abs();
        if delta > price_feed.conf as i128 {
            return false;
        }
        true
    }

    pub fn borrow(asset: u128, feed_id: u128, amount: u128, expected_feed: u128) -> u128 {
        let _ = asset;
        require(feed_id == expected_feed);
        let price = pyth::get_price_feed(feed_id);
        amount * price
    }
}

fn require(_ok: bool) {}

mod pyth {
    pub fn get_price_feed(_feed_id: u128) -> u128 {
        1
    }
}
