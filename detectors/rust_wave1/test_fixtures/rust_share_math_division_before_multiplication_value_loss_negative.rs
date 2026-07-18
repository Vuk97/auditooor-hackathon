pub struct LendingVault {
    pub total_collateral: u128,
    pub total_shares: u128,
    pub collateral_balances: Vec<(u64, u128)>,
}

impl LendingVault {
    pub fn redeem_collateral_mul_before_div(
        &mut self,
        user: u64,
        shares_to_redeem: u128,
    ) -> u128 {
        let collateral_payout = shares_to_redeem
            .checked_mul(self.total_collateral)
            .expect("share payout overflow")
            .checked_div(self.total_shares)
            .expect("nonzero share supply");

        self.total_collateral -= collateral_payout;
        self.total_shares -= shares_to_redeem;
        self.collateral_balances.push((user, collateral_payout));
        collateral_payout
    }
}
