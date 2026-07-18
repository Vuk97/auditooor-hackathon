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

pub struct Position {
    pub collateral: u128,
    pub debt: u128,
}

pub struct OracleBook {
    pub max_heartbeat: u64,
    pub price_staleness_threshold: u64,
    pub last_price: Option<CachedPrice>,
    pub asset_config: AssetConfig,
}

impl OracleBook {
    pub fn liquidation_price_accepts_stale_round(
        &self,
        round: OracleRound,
        now: u64,
        position: Position,
    ) -> u128 {
        let oracle_age = now.saturating_sub(round.updated_at);
        if oracle_age > self.max_heartbeat {
            return round.answer;
        }

        let collateral_value = position.collateral.saturating_mul(round.answer);
        position.debt.saturating_sub(collateral_value)
    }

    pub fn cached_batch_price_ignores_asset_freshness(
        &self,
        now: u64,
    ) -> Result<u128, &'static str> {
        if let Some(cached) = self.last_price {
            let cache_age = now.saturating_sub(cached.updated_at);
            if cache_age <= self.price_staleness_threshold {
                return Ok(cached.price);
            }
        }

        if !self.asset_config.enabled {
            return Err("asset disabled");
        }
        fetch_fresh_price(self.asset_config.max_age, now)
    }
}

fn fetch_fresh_price(_max_age: u64, _now: u64) -> Result<u128, &'static str> {
    Ok(100)
}
