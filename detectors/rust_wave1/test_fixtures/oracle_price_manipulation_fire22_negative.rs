pub enum Error {
    Stale,
    Deviation,
}

pub struct FeedRound {
    pub price: u128,
    pub updated_at: u64,
}

pub struct OracleVersion {
    pub price: u128,
    pub valid: bool,
    pub timestamp: u64,
}

pub struct PriceReport {
    pub price: u128,
    pub publish_time: u64,
}

pub struct PoolState {
    pub base_balance: u128,
    pub quote_balance: u128,
}

pub struct SafeOracleBook {
    pub max_heartbeat: u64,
    pub max_deviation_bps: u128,
    pub cached_price: u128,
    pub last_update: u64,
    pub last_version: OracleVersion,
    pub pmm_state: PoolState,
}

impl SafeOracleBook {
    pub fn ensure_fresh(
        &self,
        updated_at: u64,
        now: u64,
        max_heartbeat: u64,
    ) -> Result<(), Error> {
        if now.saturating_sub(updated_at) > max_heartbeat {
            return Err(Error::Stale);
        }
        Ok(())
    }

    pub fn ensure_deviation(
        &self,
        candidate_price: u128,
        oracle_price: u128,
    ) -> Result<(), Error> {
        let deviation = candidate_price.abs_diff(oracle_price);
        if deviation > self.max_deviation_bps {
            return Err(Error::Deviation);
        }
        Ok(())
    }

    pub fn get_price_rejects_stale_heartbeat(
        &self,
        round: FeedRound,
        now: u64,
    ) -> Result<u128, Error> {
        self.ensure_fresh(round.updated_at, now, self.max_heartbeat)?;
        Ok(round.price)
    }

    pub fn at_version_expired_marks_invalid(
        &self,
        version: OracleVersion,
        now: u64,
        commit_timeout: u64,
    ) -> OracleVersion {
        let expired = now.saturating_sub(version.timestamp) > commit_timeout;
        if expired {
            return OracleVersion {
                price: self.last_version.price,
                valid: false,
                timestamp: now,
            };
        }
        version
    }

    pub fn cache_price_from_report_with_bounds(
        &mut self,
        report: PriceReport,
        oracle_price: u128,
        now: u64,
    ) -> Result<u128, Error> {
        self.ensure_fresh(report.publish_time, now, self.max_heartbeat)?;
        self.ensure_deviation(report.price, oracle_price)?;
        self.cached_price = report.price;
        Ok(self.cached_price)
    }

    pub fn pmm_internal_price_with_bounds(
        &self,
        oracle_price: u128,
        now: u64,
    ) -> Result<u128, Error> {
        self.ensure_fresh(self.last_update, now, self.max_heartbeat)?;
        let base_balance = self.pmm_state.base_balance;
        let quote_balance = self.pmm_state.quote_balance;
        let internal_price = quote_balance.saturating_mul(1_000_000) / base_balance;
        self.ensure_deviation(internal_price, oracle_price)?;
        Ok(internal_price)
    }
}
