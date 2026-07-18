pub const PIPS_DENOMINATOR: u128 = 1_000_000;

#[derive(Debug, PartialEq, Eq)]
pub enum MathError {
    DebtDecayUnderflow,
    FeeAccumulatorOverflow,
    NarrowOverflow,
}

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
        swap_fee: u128,
    ) -> Result<u128, MathError> {
        let protocol_fee_amount = if swap_fee == protocol_fee {
            fee_amount
        } else {
            (amount_in + fee_amount) * protocol_fee / PIPS_DENOMINATOR
        };
        self.protocol_fees = self
            .protocol_fees
            .checked_add(protocol_fee_amount)
            .ok_or(MathError::FeeAccumulatorOverflow)?;
        Ok(protocol_fee_amount)
    }

    pub fn decay_debt_checked(&mut self, decay: u128) -> Result<u128, MathError> {
        let remaining_debt = self
            .total_debt
            .checked_sub(decay)
            .ok_or(MathError::DebtDecayUnderflow)?;
        self.total_debt = remaining_debt;
        self.last_price = remaining_debt;
        Ok(remaining_debt)
    }

    pub fn settle_lane_amount(&mut self, requested_amount: u128) -> Result<u64, MathError> {
        let settled_amount = u64::try_from(requested_amount)
            .map_err(|_| MathError::NarrowOverflow)?;
        self.protocol_fees = self
            .protocol_fees
            .checked_add(settled_amount as u128)
            .ok_or(MathError::FeeAccumulatorOverflow)?;
        Ok(settled_amount)
    }
}
