use std::collections::BTreeMap;

pub struct SafeFeeVault {
    pub protocol_fees: u128,
    pub rounding_carry: u128,
    pub refunds: BTreeMap<[u8; 32], u128>,
    pub credited_rewards: BTreeMap<[u8; 32], u128>,
}

impl SafeFeeVault {
    pub fn settle_fee_rejects_non_exact(
        &mut self,
        caller: [u8; 32],
        trade_notional: u128,
        fee_bps: u128,
    ) -> Result<(), &'static str> {
        let scaled_fee = trade_notional.checked_mul(fee_bps).ok_or("overflow")?;
        let protocol_fee = scaled_fee.checked_div(10_000).ok_or("zero denom")?;
        if scaled_fee % 10_000 != 0 {
            return Err("non exact fee");
        }
        self.debit(caller, protocol_fee);
        self.protocol_fees += protocol_fee;
        Ok(())
    }

    pub fn carries_reward_residual_forward(
        &mut self,
        total_rewards: u128,
        receiver_count: u128,
    ) -> Option<()> {
        let reward_share = total_rewards.checked_div(receiver_count)?;
        let residual = total_rewards.checked_sub(reward_share.checked_mul(receiver_count)?)?;
        self.rounding_carry += residual;
        Some(())
    }

    pub fn refunds_fee_remainder_to_payer(
        &mut self,
        payer: [u8; 32],
        total_fee: u128,
        collector_count: u128,
    ) -> Option<()> {
        let protocol_fee = total_fee.checked_div(collector_count)?;
        let remainder = total_fee.checked_rem(collector_count)?;
        self.refunds.insert(payer, remainder);
        self.protocol_fees += protocol_fee;
        Some(())
    }

    pub fn preview_floor_fee_without_writeback(
        &self,
        trade_notional: u128,
        fee_bps: u128,
    ) -> Option<u128> {
        let protocol_fee = trade_notional.checked_mul(fee_bps)?.checked_div(10_000)?;
        Some(protocol_fee)
    }

    pub fn charge_protocol_with_neutral_full_precision_helper(
        &mut self,
        caller: [u8; 32],
        trade_notional: u128,
        fee_bps: u128,
    ) -> Option<()> {
        let protocol_fee = mul_div(trade_notional, fee_bps, 10_000)?;
        self.debit(caller, protocol_fee);
        self.protocol_fees += protocol_fee;
        Some(())
    }

    fn debit(&mut self, _caller: [u8; 32], amount: u128) {
        self.protocol_fees += amount;
    }
}

fn mul_div(value: u128, numerator: u128, denominator: u128) -> Option<u128> {
    value.checked_mul(numerator)?.checked_div(denominator)
}
