pub struct OracleSample {
    pub price: u128,
    pub publish_time: u64,
    pub confidence: u128,
    pub source_id: u64,
}

pub struct CachedOracle {
    pub last_price: u128,
    pub last_publish_time: u64,
    pub max_deviation_bps: u128,
    pub max_age: u64,
    pub max_confidence: u128,
    pub trusted_source_id: u64,
}

impl CachedOracle {
    pub fn update_price_cached_baseline_before_freshness(
        &mut self,
        sample: OracleSample,
        now: u64,
    ) -> Result<u128, &'static str> {
        let previous_price = self.last_price;
        let price_delta = sample.price.abs_diff(previous_price);
        ensure(
            price_delta * 10_000 <= previous_price * self.max_deviation_bps,
            "deviation",
        )?;

        self.last_price = sample.price;

        ensure(now.saturating_sub(sample.publish_time) <= self.max_age, "stale")?;
        ensure(sample.confidence <= self.max_confidence, "wide confidence")?;
        ensure(sample.source_id == self.trusted_source_id, "wrong source")?;
        self.last_publish_time = sample.publish_time;
        Ok(sample.price)
    }

    pub fn heartbeat_rolls_timestamp_cache_before_round_guard(
        &mut self,
        sample: OracleSample,
        now: u64,
    ) -> Result<u64, &'static str> {
        let previous_publish_time = self.last_publish_time;
        ensure(sample.publish_time >= previous_publish_time, "old round")?;
        ensure(now.saturating_sub(previous_publish_time) <= self.max_age * 2, "heartbeat")?;

        self.last_publish_time = sample.publish_time;

        ensure(sample.price > 0, "zero price")?;
        ensure(sample.confidence <= self.max_confidence, "wide confidence")?;
        Ok(sample.publish_time)
    }
}

fn ensure(condition: bool, error: &'static str) -> Result<(), &'static str> {
    if condition {
        Ok(())
    } else {
        Err(error)
    }
}
