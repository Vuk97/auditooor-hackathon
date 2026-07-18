pub struct Account {
    pub market_id: u64,
    pub position_size: u128,
    pub collateral: u128,
    pub margin_requirement: u128,
}

pub struct Order {
    pub qty: u128,
}

pub struct MarginRequest {
    pub underlying_price: u128,
}

pub struct FillPayload {
    pub oracle_price: u128,
}

pub struct PerpEngine {
    pub last_fill_value: u128,
}

impl PerpEngine {
    pub fn settle_margin_from_request(
        &mut self,
        account: &mut Account,
        request: MarginRequest,
    ) -> u128 {
        let notional = account.position_size.saturating_mul(request.underlying_price);
        account.margin_requirement = notional / 10;
        account.margin_requirement
    }

    pub fn liquidation_value_from_submitted_mark(
        &self,
        account: &Account,
        mark_price: u128,
    ) -> u128 {
        let liquidation_value = account.position_size * mark_price;
        liquidation_value.saturating_sub(account.collateral)
    }

    pub fn execute_fill_from_payload_oracle(
        &mut self,
        order: &Order,
        payload: FillPayload,
    ) -> u128 {
        let fill_value = order.qty.saturating_mul(payload.oracle_price);
        self.last_fill_value = fill_value;
        fill_value
    }
}
