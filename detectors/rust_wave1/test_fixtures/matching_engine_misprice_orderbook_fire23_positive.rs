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

pub struct ReplayableBook {
    pub last_px: u128,
    pub bid_px: u128,
    pub ask_px: u128,
}

impl ReplayableBook {
    pub fn best_bid(&self) -> u128 {
        self.bid_px
    }

    pub fn best_ask(&self) -> u128 {
        self.ask_px
    }
}

pub struct MatchingEngine {
    pub orderbook: ReplayableBook,
}

impl MatchingEngine {
    pub fn mark_margin_from_replayed_last_trade(&self, account: &Account) -> u128 {
        let mark_price = self.orderbook.last_px;
        let notional = account.position_size * mark_price;
        notional / 10 + account.collateral
    }

    pub fn execute_fill_selects_wrong_side(&self, order: &Order) -> u128 {
        let fill_price = match order.side {
            Side::Buy => self.orderbook.best_bid(),
            Side::Sell => self.orderbook.best_ask(),
        };
        order.qty * fill_price
    }

    pub fn maintenance_margin_from_raw_book_ask(&self, account: &Account) -> u128 {
        let px = self.orderbook.best_ask();
        let maintenance_margin = account.position_size * px / 20;
        maintenance_margin.saturating_sub(account.collateral)
    }
}
