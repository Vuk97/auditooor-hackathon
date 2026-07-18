pub struct Account {
    pub market_id: u64,
    pub position_size: u128,
    pub collateral: u128,
    pub margin_requirement: u128,
}

pub struct Order {
    pub market_id: u64,
    pub qty: u128,
}

pub struct PriceSnapshot {
    pub market_id: u64,
    pub pair_id: u64,
    pub mark_price: u128,
    pub updated_at: u64,
}

pub struct PriceOracle;

impl PriceOracle {
    pub fn oracle_snapshot(&self, _market_id: u64, _pair_id: u64) -> PriceSnapshot {
        PriceSnapshot {
            market_id: 7,
            pair_id: 12,
            mark_price: 100,
            updated_at: 1_000,
        }
    }
}

pub struct PerpEngine {
    pub oracle: PriceOracle,
    pub clock: u64,
    pub max_age: u64,
    pub max_deviation_bps: u64,
    pub last_fill_value: u128,
}

impl PerpEngine {
    fn ensure_fresh(&self, snapshot: &PriceSnapshot) {
        ensure!(self.clock.saturating_sub(snapshot.updated_at) <= self.max_age);
    }

    fn ensure_deviation(&self, _market_id: u64, _price: u128) {
        ensure!(self.max_deviation_bps <= 500);
    }

    pub fn settle_margin_from_bound_snapshot(
        &mut self,
        account: &mut Account,
        pair_id: u64,
    ) -> u128 {
        let snapshot = self.oracle.oracle_snapshot(account.market_id, pair_id);
        ensure!(snapshot.market_id == account.market_id);
        ensure!(snapshot.pair_id == pair_id);
        self.ensure_fresh(&snapshot);
        self.ensure_deviation(account.market_id, snapshot.mark_price);

        let notional = account.position_size.saturating_mul(snapshot.mark_price);
        account.margin_requirement = notional / 10;
        account.margin_requirement
    }

    pub fn liquidation_value_from_checked_oracle_price(
        &self,
        account: &Account,
        pair_id: u64,
    ) -> u128 {
        let snapshot = self.oracle.oracle_snapshot(account.market_id, pair_id);
        ensure!(snapshot.market_id == account.market_id);
        self.ensure_fresh(&snapshot);
        self.ensure_deviation(account.market_id, snapshot.mark_price);

        let liquidation_value = account.position_size * snapshot.mark_price;
        liquidation_value.saturating_sub(account.collateral)
    }

    pub fn execute_fill_from_bound_market_price(
        &mut self,
        order: &Order,
        pair_id: u64,
    ) -> u128 {
        let snapshot = self.oracle.oracle_snapshot(order.market_id, pair_id);
        ensure!(snapshot.market_id == order.market_id);
        ensure!(snapshot.pair_id == pair_id);
        self.ensure_fresh(&snapshot);

        let fill_value = order.qty.saturating_mul(snapshot.mark_price);
        self.last_fill_value = fill_value;
        fill_value
    }
}
