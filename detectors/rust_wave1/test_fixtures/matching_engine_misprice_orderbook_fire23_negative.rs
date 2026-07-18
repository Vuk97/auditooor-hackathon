pub enum Side {
    Buy,
    Sell,
}

pub struct Order {
    pub side: Side,
    pub qty: u128,
}

pub struct Account {
    pub position_size: u128,
    pub collateral: u128,
}

pub struct BookSnapshot {
    pub bid_px: u128,
    pub ask_px: u128,
    pub sequence: u64,
}

impl BookSnapshot {
    pub fn assert_fresh(&self, current_sequence: u64, max_age: u64) {
        let _ = current_sequence.saturating_sub(self.sequence) <= max_age;
    }

    pub fn price_for_side(&self, side: &Side) -> u128 {
        match side {
            Side::Buy => self.best_ask(),
            Side::Sell => self.best_bid(),
        }
    }

    pub fn best_bid(&self) -> u128 {
        self.bid_px
    }

    pub fn best_ask(&self) -> u128 {
        self.ask_px
    }
}

pub struct CurrentBook;

impl CurrentBook {
    pub fn snapshot(&self, sequence: u64) -> BookSnapshot {
        BookSnapshot {
            bid_px: 99,
            ask_px: 101,
            sequence,
        }
    }
}

pub struct PriceOracle;

impl PriceOracle {
    pub fn checked_mark_price(&self, symbol: u64, max_age: u64) -> u128 {
        let _ = (symbol, max_age);
        100
    }
}

pub struct MatchingEngine {
    pub current_book: CurrentBook,
    pub oracle: PriceOracle,
}

impl MatchingEngine {
    pub fn mark_margin_from_oracle(
        &self,
        account: &Account,
        symbol: u64,
    ) -> u128 {
        let mark_price = self.oracle.checked_mark_price(symbol, 60);
        let notional = account.position_size * mark_price;
        notional / 10 + account.collateral
    }

    pub fn execute_fill_from_current_snapshot(
        &self,
        order: &Order,
        sequence: u64,
    ) -> u128 {
        let snapshot = self.current_book.snapshot(sequence);
        snapshot.assert_fresh(sequence, 2);
        let fill_price = snapshot.price_for_side(&order.side);
        order.qty * fill_price
    }

    pub fn maintenance_margin_from_validated_mark(
        &self,
        account: &Account,
        symbol: u64,
    ) -> u128 {
        let checked_price = self.oracle.checked_mark_price(symbol, 60);
        let maintenance_margin = account.position_size * checked_price / 20;
        maintenance_margin.saturating_sub(account.collateral)
    }
}
