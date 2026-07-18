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

pub struct OracleBook {
    pub max_heartbeat: u64,
    pub cached_price: u128,
    pub last_version: OracleVersion,
    pub pmm_state: PoolState,
}

impl OracleBook {
    pub fn get_price_accepts_stale_heartbeat(&self, round: FeedRound, now: u64) -> u128 {
        let age = now.saturating_sub(round.updated_at);
        if age > self.max_heartbeat {
            return round.price;
        }
        round.price
    }

    pub fn at_version_expired_returns_previous(
        &self,
        version: OracleVersion,
        now: u64,
        commit_timeout: u64,
    ) -> OracleVersion {
        let expired = now.saturating_sub(version.timestamp) > commit_timeout;
        if expired {
            return self.last_version;
        }
        version
    }

    pub fn cache_price_from_report_without_bounds(
        &mut self,
        report: PriceReport,
        now: u64,
    ) -> u128 {
        let _age = now.saturating_sub(report.publish_time);
        self.cached_price = report.price;
        self.cached_price
    }

    pub fn pmm_internal_price_without_bounds(&self) -> u128 {
        let base_balance = self.pmm_state.base_balance;
        let quote_balance = self.pmm_state.quote_balance;
        let internal_price = quote_balance.saturating_mul(1_000_000) / base_balance;
        internal_price
    }
}
