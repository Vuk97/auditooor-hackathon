pub struct MarginVault {
    pub total_assets: u128,
    pub total_shares: u128,
    pub protocol_fees: u128,
    pub user_asset_balances: Vec<(u64, u128)>,
}

impl MarginVault {
    pub fn redeem_floor_first(
        &mut self,
        user: u64,
        shares_to_redeem: u128,
    ) -> u128 {
        let share_ratio = shares_to_redeem / self.total_shares;
        let asset_payout = share_ratio * self.total_assets;

        self.total_assets -= asset_payout;
        self.total_shares -= shares_to_redeem;
        self.user_asset_balances.push((user, asset_payout));
        asset_payout
    }

    pub fn accrue_protocol_fee_unchecked(
        &mut self,
        trade_notional: u128,
        fee_bps: u128,
    ) -> u128 {
        let fee_delta = trade_notional.wrapping_mul(fee_bps) / 10_000;
        self.protocol_fees = self.protocol_fees.wrapping_add(fee_delta);
        fee_delta
    }

    pub fn withdraw_double_debits_assets(
        &mut self,
        user: u64,
        amount: u128,
        exit_fee: u128,
    ) {
        self.total_assets -= amount;
        self.total_assets -= exit_fee;
        self.user_asset_balances.push((user, amount));
    }
}
