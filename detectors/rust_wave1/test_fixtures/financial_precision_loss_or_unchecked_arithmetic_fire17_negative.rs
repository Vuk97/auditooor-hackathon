pub struct MarginVault {
    pub total_assets: u128,
    pub total_shares: u128,
    pub protocol_fees: u128,
    pub user_asset_balances: Vec<(u64, u128)>,
}

impl MarginVault {
    pub fn redeem_checked_mul_before_div(
        &mut self,
        user: u64,
        shares_to_redeem: u128,
    ) -> u128 {
        let asset_payout = shares_to_redeem
            .checked_mul(self.total_assets)
            .expect("payout overflow")
            .checked_div(self.total_shares)
            .expect("nonzero shares");

        self.total_assets = self
            .total_assets
            .checked_sub(asset_payout)
            .expect("asset underflow");
        self.total_shares = self
            .total_shares
            .checked_sub(shares_to_redeem)
            .expect("share underflow");
        self.user_asset_balances.push((user, asset_payout));
        asset_payout
    }

    pub fn accrue_protocol_fee_checked(
        &mut self,
        trade_notional: u128,
        fee_bps: u128,
    ) -> u128 {
        let fee_delta = trade_notional
            .checked_mul(fee_bps)
            .expect("fee overflow")
            .checked_div(10_000)
            .expect("basis points denominator");
        self.protocol_fees = self
            .protocol_fees
            .checked_add(fee_delta)
            .expect("fee ledger overflow");
        fee_delta
    }

    pub fn withdraw_with_single_checked_debit(
        &mut self,
        user: u64,
        amount: u128,
        exit_fee: u128,
    ) {
        let total_debit = amount.checked_add(exit_fee).expect("debit overflow");
        self.total_assets = self
            .total_assets
            .checked_sub(total_debit)
            .expect("asset underflow");
        self.user_asset_balances.push((user, amount));
    }
}
