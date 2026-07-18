use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct OracleConsumer;

pub struct RoundData {
    pub answer: i128,
    pub started_at: u64,
}

pub struct PriceFeed;
pub struct SequencerUptimeFeed;

impl PriceFeed {
    pub fn latest_round_data(&self) -> RoundData {
        RoundData {
            answer: 42,
            started_at: 0,
        }
    }
}

impl SequencerUptimeFeed {
    pub fn latest_round_data(&self) -> RoundData {
        RoundData {
            answer: 1,
            started_at: 10,
        }
    }
}

#[contractimpl]
impl OracleConsumer {
    pub fn get_price(
        env: Env,
        sequencer_uptime_feed: SequencerUptimeFeed,
        price_feed: PriceFeed,
    ) -> i128 {
        let uptime = sequencer_uptime_feed.latest_round_data();
        let grace_period = 3600_u64;
        let time_since_up = env.ledger().timestamp() - uptime.started_at;
        assert!(time_since_up <= grace_period);

        let round = price_feed.latest_round_data();
        round.answer
    }
}
