use soroban_sdk::{contract, contractimpl};

pub struct Price { pub price: i128, pub expo: i32 }
pub struct PriceFeed { pub id: [u8; 32] }
pub struct OracleAccount;

impl PriceFeed {
    pub fn get_price_unchecked(&self) -> Price {
        Price { price: 100_000_000, expo: -8 }
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
    // BUG: caller-supplied oracle_account is loaded and priced without checking PriceFeed.id.
    pub fn collateral_value(oracle_account: OracleAccount, amount: u128) -> u128 {
        let price_feed = pyth::load_price_feed_from_account_info(oracle_account);
        let price = price_feed.get_price_unchecked();
        amount * price.price as u128
    }
}
