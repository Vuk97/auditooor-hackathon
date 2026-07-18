use soroban_sdk::{contract, contractimpl};

pub struct RoundData {
    pub answer: i128,
    pub updated_at: u64,
}

pub struct PriceFeed {
    pub conf: u64,
}

fn latest_round_data() -> RoundData {
    RoundData { answer: -500, updated_at: 100 }
}

fn block_timestamp() -> u64 {
    200
}

#[contract]
pub struct OracleAdapter;

#[contractimpl]
impl OracleAdapter {
    // BUG: stale check exists, but negative signed answer can wrap when cast.
    pub fn current_price() -> u128 {
        let r = latest_round_data();
        let now = block_timestamp();
        assert!(now - r.updated_at < 3600, "stale");
        r.answer as u128
    }

    // BUG: negative deviation passes because confidence is checked one-way.
    pub fn update_index(new_price: i128, current_index: i128, price_feed: PriceFeed) -> bool {
        let delta = new_price - current_index;
        if delta > price_feed.conf as i128 {
            return false;
        }
        true
    }

    // BUG: caller can select a different feed for this asset.
    pub fn borrow(asset: u128, feed_id: u128, amount: u128) -> u128 {
        let _ = asset;
        let price = pyth::get_price_feed(feed_id);
        amount * price
    }
}

mod pyth {
    pub fn get_price_feed(_feed_id: u128) -> u128 {
        1
    }
}
