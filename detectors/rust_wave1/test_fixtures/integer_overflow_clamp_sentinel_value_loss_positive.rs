pub const PIPS_DENOMINATOR: u128 = 1_000_000;

pub struct PoolState {
    pub protocol_fees: u128,
    pub total_debt: u128,
    pub last_price: u128,
}

impl PoolState {
    pub fn swap_step(
        &mut self,
        amount_in: u128,
        fee_amount: u128,
        protocol_fee: u128,
    ) -> u128 {
        let protocol_fee_amount =
            (amount_in + fee_amount) * protocol_fee / PIPS_DENOMINATOR;
        self.protocol_fees += protocol_fee_amount;
        protocol_fee_amount
    }

    pub fn decay_debt_to_zero(&mut self, decay: u128) -> u128 {
        let remaining_debt = self.total_debt.checked_sub(decay).unwrap_or(0);
        self.total_debt = remaining_debt;
        self.last_price = remaining_debt;
        remaining_debt
    }

    pub fn settle_lane_amount(&mut self, requested_amount: u128) -> u64 {
        let settled_amount = requested_amount.min(u64::MAX as u128) as u64;
        self.protocol_fees += settled_amount as u128;
        settled_amount
    }
}
