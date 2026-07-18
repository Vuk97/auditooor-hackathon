pub struct LendingVault {
    pub protocol_fees: u128,
    pub rewards_paid: u128,
    pub collateral_seized: u128,
}

fn ceil_div(numerator: u128, denominator: u128) -> Option<u128> {
    if denominator == 0 {
        return None;
    }
    numerator.checked_add(denominator - 1)?.checked_div(denominator)
}

impl LendingVault {
    pub fn charge_protocol_fee(
        &mut self,
        user_notional: u128,
        fee_denominator: u128,
        protocol_fee_bps: u128,
    ) -> Option<u128> {
        let scaled = user_notional.checked_mul(protocol_fee_bps)?;
        let protocol_fee = scaled.checked_div(fee_denominator)?;
        self.protocol_fees += protocol_fee;
        Some(protocol_fee)
    }

    pub fn claim_rewards(
        &mut self,
        user_weight: u128,
        total_weight: u128,
        epoch_reward: u128,
    ) -> Option<u128> {
        if total_weight == 0 {
            return None;
        }
        if user_weight % total_weight != 0 {
            return None;
        }
        let reward_units = user_weight / total_weight;
        let reward_payout = reward_units.checked_mul(epoch_reward)?;
        self.rewards_paid += reward_payout;
        Some(reward_payout)
    }

    pub fn liquidate_position(
        &mut self,
        borrower_debt: u128,
        liquidation_divisor: u128,
    ) -> Option<u128> {
        let collateral_seized = ceil_div(borrower_debt, liquidation_divisor)?;
        self.collateral_seized += collateral_seized;
        Some(collateral_seized)
    }
}
