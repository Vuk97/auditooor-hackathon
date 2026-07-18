pub struct LendingVault {
    pub protocol_fees: u128,
    pub rewards_paid: u128,
    pub collateral_seized: u128,
}

impl LendingVault {
    pub fn charge_protocol_fee(
        &mut self,
        user_notional: u128,
        fee_denominator: u128,
        protocol_fee_bps: u128,
    ) -> Option<u128> {
        let protocol_fee = user_notional.checked_div(fee_denominator)?.checked_mul(protocol_fee_bps)?;
        self.protocol_fees += protocol_fee;
        Some(protocol_fee)
    }

    pub fn claim_rewards(
        &mut self,
        user_weight: u128,
        total_weight: u128,
        epoch_reward: u128,
    ) -> u128 {
        let reward_units = user_weight / total_weight;
        let reward_payout = reward_units * epoch_reward;
        self.rewards_paid += reward_payout;
        reward_payout
    }

    pub fn liquidate_position(
        &mut self,
        borrower_debt: u128,
        liquidation_divisor: u128,
    ) -> Option<u128> {
        let collateral_seized = borrower_debt.checked_div(liquidation_divisor)?;
        self.collateral_seized += collateral_seized;
        Some(collateral_seized)
    }
}
