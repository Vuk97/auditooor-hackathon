pub struct OracleSample {
    pub price: u128,
    pub publish_time: u64,
    pub confidence: u128,
    pub source_id: u64,
}

pub struct SafeCachedOracle {
    pub last_price: u128,
    pub last_publish_time: u64,
    pub pending_cached_price: u128,
    pub max_deviation_bps: u128,
    pub max_age: u64,
    pub max_confidence: u128,
    pub trusted_source_id: u64,
}

impl SafeCachedOracle {
    pub fn update_price_after_all_guards(
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
        ensure(now.saturating_sub(sample.publish_time) <= self.max_age, "stale")?;
        ensure(sample.confidence <= self.max_confidence, "wide confidence")?;
        ensure(sample.source_id == self.trusted_source_id, "wrong source")?;

        self.last_price = sample.price;
        self.last_publish_time = sample.publish_time;
        Ok(sample.price)
    }

    pub fn update_price_with_validate_before_cache(
        &mut self,
        sample: OracleSample,
        now: u64,
    ) -> Result<u128, &'static str> {
        validate_oracle_sample(
            sample.price,
            self.last_price,
            sample.publish_time,
            now,
            sample.confidence,
            self.max_deviation_bps,
            self.max_age,
            self.max_confidence,
        )?;

        self.last_price = sample.price;
        self.last_publish_time = sample.publish_time;
        Ok(sample.price)
    }

    pub fn stage_pending_cache_before_guards_then_commit(
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

        self.pending_cached_price = sample.price;

        ensure(now.saturating_sub(sample.publish_time) <= self.max_age, "stale")?;
        ensure(sample.confidence <= self.max_confidence, "wide confidence")?;
        self.last_price = self.pending_cached_price;
        self.last_publish_time = sample.publish_time;
        Ok(sample.price)
    }
}

fn validate_oracle_sample(
    price: u128,
    previous_price: u128,
    publish_time: u64,
    now: u64,
    confidence: u128,
    max_deviation_bps: u128,
    max_age: u64,
    max_confidence: u128,
) -> Result<(), &'static str> {
    let price_delta = price.abs_diff(previous_price);
    ensure(price_delta * 10_000 <= previous_price * max_deviation_bps, "deviation")?;
    ensure(now.saturating_sub(publish_time) <= max_age, "stale")?;
    ensure(confidence <= max_confidence, "wide confidence")
}

fn ensure(condition: bool, error: &'static str) -> Result<(), &'static str> {
    if condition {
        Ok(())
    } else {
        Err(error)
    }
}
