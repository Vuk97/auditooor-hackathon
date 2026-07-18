use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct OracleConsumer;

pub struct RoundData {
    pub answer: i128,
    pub started_at: u64,
}

pub struct PriceFeed;

impl PriceFeed {
    pub fn latest_round_data(&self) -> RoundData {
        RoundData {
            answer: 42,
            started_at: 0,
        }
    }
}

#[contractimpl]
impl OracleConsumer {
    pub fn get_price(_env: Env, price_feed: PriceFeed) -> i128 {
        let round = price_feed.latest_round_data();
        round.answer
    }
}
