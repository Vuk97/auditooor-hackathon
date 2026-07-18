pub struct LendingDesk {
    pub protocol_fees: u128,
    pub treasury_payouts: Vec<(u64, u128)>,
    pub receiver_payouts: Vec<(u64, u128)>,
    pub final_tvl: u128,
    pub claim_tvl: u128,
}

impl LendingDesk {
    pub fn connect_offer_fee_floor(
        &mut self,
        borrower: u64,
        principal: u128,
        borrow_duration: u128,
        fee_per_day: u128,
    ) -> u128 {
        let fee_percentage = (borrow_duration * fee_per_day) / 86_400;
        let fee_amount = principal * fee_percentage / 10_000;
        self.protocol_fees += fee_amount;
        self.receiver_payouts.push((borrower, principal - fee_amount));
        fee_amount
    }

    pub fn before_withdraw_floor_first(
        &mut self,
        user: u64,
        assets: u128,
    ) -> u128 {
        let payout_ratio = assets / self.final_tvl;
        let entitled_amount = payout_ratio * self.claim_tvl;
        self.treasury_payouts.push((user, entitled_amount));
        entitled_amount
    }
}
