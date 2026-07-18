pub struct LendingVault {
    pub total_collateral: u128,
    pub total_shares: u128,
    pub collateral_balances: Vec<(u64, u128)>,
}

impl LendingVault {
    pub fn redeem_collateral_floor_first(
        &mut self,
        user: u64,
        shares_to_redeem: u128,
    ) -> u128 {
        let share_ratio = shares_to_redeem / self.total_shares;
        let collateral_payout = share_ratio * self.total_collateral;

        self.total_collateral -= collateral_payout;
        self.total_shares -= shares_to_redeem;
        self.collateral_balances.push((user, collateral_payout));
        collateral_payout
    }
}
