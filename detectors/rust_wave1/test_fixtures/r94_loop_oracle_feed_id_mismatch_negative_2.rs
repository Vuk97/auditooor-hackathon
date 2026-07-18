use soroban_sdk::{contract, contractimpl};

pub struct Price { pub price: i128, pub expo: i32 }
pub struct PriceFeed { pub id: [u8; 32] }
pub struct OracleAccount;
pub struct MarketConfig { pub expected_feed_id: [u8; 32] }

impl PriceFeed {
    pub fn get_price_no_older_than(&self, _now: u64, _max_age: u64) -> Option<Price> {
        Some(Price { price: 100_000_000, expo: -8 })
    }
}

pub mod pyth {
    use super::{OracleAccount, PriceFeed};
    pub fn load_price_feed_from_account_info(_account: OracleAccount) -> PriceFeed {
        PriceFeed { id: [7; 32] }
    }
}

#[contract]
pub struct LendingMarket;

#[contractimpl]
impl LendingMarket {
    // SAFE: feed metadata is bound to configured market feed before pricing.
    pub fn collateral_value(
        oracle_account: OracleAccount,
        amount: u128,
        config: MarketConfig,
        now: u64,
    ) -> u128 {
        let price_feed = pyth::load_price_feed_from_account_info(oracle_account);
        assert_eq!(price_feed.id, config.expected_feed_id);
        let price = price_feed.get_price_no_older_than(now, 60).unwrap();
        amount * price.price as u128
    }
}
