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

pub struct PriceOracle;

impl PriceOracle {
    pub fn checked_mark_price(&self, _symbol: u64, _max_age: u64) -> u128 {
        100
    }
}

pub struct CurrentBook {
    pub bid_px: u128,
    pub ask_px: u128,
}

impl CurrentBook {
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

pub struct PerpEngine {
    pub oracle: PriceOracle,
    pub current_book: CurrentBook,
}

impl PerpEngine {
    pub fn compute_margin_from_oracle(&self, account: &Account, symbol: u64) -> u128 {
        let mark_price = self.oracle.checked_mark_price(symbol, 60);
        let notional = account.position_size * mark_price;
        notional / 10 + account.collateral
    }

    pub fn execute_fill_with_current_book(&self, order: &Order) -> u128 {
        let px = self.current_book.price_for_side(&order.side);
        order.qty * px
    }

    pub fn liquidation_value_from_checked_price(
        &self,
        account: &Account,
        symbol: u64,
    ) -> u128 {
        let checked_price = self.oracle.checked_mark_price(symbol, 60);
        let liquidation_value = account.position_size * checked_price;
        liquidation_value.saturating_sub(account.collateral)
    }
}
