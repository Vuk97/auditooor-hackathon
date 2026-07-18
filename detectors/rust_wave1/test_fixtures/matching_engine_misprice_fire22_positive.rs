pub enum Side {
    Buy,
    Sell,
}

pub struct Order {
    pub side: Side,
    pub qty: u128,
    pub base: u128,
}

pub struct Account {
    pub position_size: u128,
    pub collateral: u128,
}

pub struct Book {
    pub last_px: u128,
    pub bid_px: u128,
    pub ask_px: u128,
}

impl Book {
    pub fn best_bid(&self) -> u128 {
        self.bid_px
    }

    pub fn best_ask(&self) -> u128 {
        self.ask_px
    }
}

pub struct PerpEngine {
    pub book: Book,
}

impl PerpEngine {
    pub fn compute_margin_from_last_px(&self, account: &Account) -> u128 {
        let notional = account.position_size * self.book.last_px;
        notional / 10 + account.collateral
    }

    pub fn execute_fill_with_wrong_side(&self, order: &Order) -> u128 {
        let px = match order.side {
            Side::Buy => self.book.best_bid(),
            Side::Sell => self.book.best_ask(),
        };
        order.qty * px
    }

    pub fn liquidation_value_from_user_px(
        &self,
        account: &Account,
        underlying_price: u128,
    ) -> u128 {
        let liquidation_value = account.position_size * underlying_price;
        liquidation_value.saturating_sub(account.collateral)
    }
}
