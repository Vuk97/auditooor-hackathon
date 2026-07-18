pub struct OracleRound {
    pub answer: u128,
    pub updated_at: u64,
}

pub struct CachedPrice {
    pub price: u128,
    pub updated_at: u64,
}

pub struct AssetConfig {
    pub max_age: u64,
    pub enabled: bool,
}

pub enum OracleError {
    StalePrice,
    AssetDisabled,
}

pub struct SafeOracleBook {
    pub max_heartbeat: u64,
    pub price_staleness_threshold: u64,
    pub last_good_price: u128,
    pub last_price: Option<CachedPrice>,
    pub asset_config: AssetConfig,
}

impl SafeOracleBook {
    pub fn liquidation_price_rejects_stale_round(
        &self,
        round: OracleRound,
        now: u64,
    ) -> Result<u128, OracleError> {
        let oracle_age = now.saturating_sub(round.updated_at);
        if oracle_age > self.max_heartbeat {
            return Err(OracleError::StalePrice);
        }

        Ok(round.answer)
    }

    pub fn liquidation_price_uses_safe_last_good_or_twap(
        &self,
        round: OracleRound,
        now: u64,
    ) -> u128 {
        let oracle_age = now.saturating_sub(round.updated_at);
        if oracle_age > self.max_heartbeat {
            return self.last_good_price.max(self.safe_twap_price());
        }

        round.answer
    }

    pub fn cached_batch_price_checks_asset_freshness_first(
        &self,
        now: u64,
    ) -> Result<u128, OracleError> {
        if !self.asset_config.enabled {
            return Err(OracleError::AssetDisabled);
        }

        if let Some(cached) = self.last_price {
            let cache_age = now.saturating_sub(cached.updated_at);
            if cache_age <= self.asset_config.max_age
                && cache_age <= self.price_staleness_threshold
            {
                return Ok(cached.price);
            }
        }

        Err(OracleError::StalePrice)
    }

    fn safe_twap_price(&self) -> u128 {
        self.last_good_price
    }
}
