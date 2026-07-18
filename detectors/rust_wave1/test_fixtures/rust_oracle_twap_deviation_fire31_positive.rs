pub struct FeedRound {
    pub price: u128,
    pub updated_at: u64,
}

pub struct PriceFeed;

impl PriceFeed {
    pub fn latest_price(&self, _asset: u64) -> u128 {
        1_000
    }
}

pub struct LastPriceData {
    pub price: u128,
    pub timestamp: u64,
}

pub struct Borrower {
    pub asset: u64,
    pub debt: u128,
    pub collateral: u128,
}

pub struct OracleError;

pub struct LendingEngine {
    pub last_price_data: LastPriceData,
}

impl LendingEngine {
    pub fn borrow_against_spot_oracle_no_twap(
        &self,
        feed: &PriceFeed,
        borrower: &mut Borrower,
        collateral_amount: u128,
    ) -> Result<u128, OracleError> {
        let spot_price = feed.latest_price(borrower.asset);
        let borrow_limit = collateral_amount.saturating_mul(spot_price) / 2;
        borrower.debt = borrower.debt.saturating_add(borrow_limit);
        Ok(borrow_limit)
    }

    pub fn get_asset_prices_batch_accepts_cached_without_guard(
        &self,
        borrower: &Borrower,
    ) -> Result<u128, OracleError> {
        let cached_price = self.last_price_data.price;
        let liquidation_value = borrower.debt.saturating_mul(cached_price);
        Ok(liquidation_value)
    }
}
