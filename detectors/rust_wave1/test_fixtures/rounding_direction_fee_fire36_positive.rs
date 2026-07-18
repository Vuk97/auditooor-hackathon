use std::collections::BTreeMap;

pub struct FeeVault {
    pub protocol_fees: u128,
    pub credited_rewards: BTreeMap<[u8; 32], u128>,
    pub share_ledger: BTreeMap<[u8; 32], u128>,
}

impl FeeVault {
    pub fn settle_floor_fee_undercharges_protocol(
        &mut self,
        caller: [u8; 32],
        trade_notional: u128,
        fee_bps: u128,
    ) -> Option<()> {
        let protocol_fee = trade_notional.checked_mul(fee_bps)?.checked_div(10_000)?;
        self.debit(caller, protocol_fee);
        self.protocol_fees += protocol_fee;
        Some(())
    }

    pub fn claim_ceil_reward_overpays_caller(
        &mut self,
        caller: [u8; 32],
        accrued_rewards: u128,
        reward_scale: u128,
    ) {
        let reward_payout = accrued_rewards.div_ceil(reward_scale);
        self.credited_rewards.insert(caller, reward_payout);
        self.transfer_reward(caller, reward_payout);
    }

    pub fn liquidate_floor_collateral_check(
        &mut self,
        borrower: [u8; 32],
        debt_amount: u128,
        collateral_price: u128,
    ) -> Option<()> {
        let required_collateral =
            debt_amount.checked_mul(collateral_price)?.checked_div(1_000_000)?;
        if self.health_after_seizure(borrower, required_collateral) >= 1 {
            self.release_collateral(borrower, required_collateral);
        }
        Some(())
    }

    pub fn mint_truncated_shares_to_recipient(
        &mut self,
        recipient: [u8; 32],
        assets: u128,
        total_supply: u128,
        total_assets: u128,
    ) -> Option<()> {
        let shares = assets.checked_mul(total_supply)?.checked_div(total_assets)? as u64;
        self.share_ledger.insert(recipient, shares as u128);
        Some(())
    }

    fn debit(&mut self, _caller: [u8; 32], amount: u128) {
        self.protocol_fees += amount;
    }

    fn transfer_reward(&mut self, _caller: [u8; 32], amount: u128) {
        self.protocol_fees = self.protocol_fees.saturating_sub(amount);
    }

    fn health_after_seizure(&self, _borrower: [u8; 32], _required: u128) -> u128 {
        1
    }

    fn release_collateral(&mut self, _borrower: [u8; 32], _required: u128) {}
}
