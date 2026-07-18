pub struct FeedRound {
    pub price: u128,
    pub updated_at: u64,
}

pub struct PriceFeed;

impl PriceFeed {
    pub fn latest_round(&self, _asset: u64) -> FeedRound {
        FeedRound {
            price: 1_000,
            updated_at: 10,
        }
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

pub enum OracleError {
    Shutdown,
    StalePrice,
    Deviation,
}

pub struct AssetConfig {
    pub max_age: u64,
}

pub struct LendingEngine {
    pub last_price_data: LastPriceData,
    pub heartbeat: u64,
    pub max_deviation_bps: u128,
    pub asset_config: AssetConfig,
    pub safe_shutdown: bool,
}

impl LendingEngine {
    pub fn borrow_against_spot_oracle_with_guards(
        &self,
        feed: &PriceFeed,
        borrower: &mut Borrower,
        collateral_amount: u128,
        now: u64,
    ) -> Result<u128, OracleError> {
        if self.safe_shutdown {
            return Err(OracleError::Shutdown);
        }
        let round = feed.latest_round(borrower.asset);
        self.ensure_fresh(round.updated_at, now)?;
        self.ensure_deviation(round.price, self.safe_twap_price(borrower.asset))?;
        let borrow_limit = collateral_amount.saturating_mul(round.price) / 2;
        borrower.debt = borrower.debt.saturating_add(borrow_limit);
        Ok(borrow_limit)
    }

    pub fn get_asset_prices_batch_rejects_stale_cache(
        &self,
        borrower: &Borrower,
        now: u64,
    ) -> Result<u128, OracleError> {
        let cache_age = now.saturating_sub(self.last_price_data.timestamp);
        if cache_age > self.asset_config.max_age {
            return Err(OracleError::StalePrice);
        }
        self.ensure_deviation(
            self.last_price_data.price,
            self.safe_twap_price(borrower.asset),
        )?;
        let liquidation_value = borrower.debt.saturating_mul(self.last_price_data.price);
        Ok(liquidation_value)
    }

    fn ensure_fresh(&self, updated_at: u64, now: u64) -> Result<(), OracleError> {
        if now.saturating_sub(updated_at) > self.heartbeat {
            return Err(OracleError::StalePrice);
        }
        Ok(())
    }

    fn ensure_deviation(&self, price: u128, twap_price: u128) -> Result<(), OracleError> {
        let diff = price.abs_diff(twap_price);
        if diff.saturating_mul(10_000) > twap_price.saturating_mul(self.max_deviation_bps) {
            return Err(OracleError::Deviation);
        }
        Ok(())
    }

    fn safe_twap_price(&self, _asset: u64) -> u128 {
        1_000
    }
}
