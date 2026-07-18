pub struct LendingDesk {
    pub protocol_fees: u128,
    pub treasury_payouts: Vec<(u64, u128)>,
    pub receiver_payouts: Vec<(u64, u128)>,
    pub final_tvl: u128,
    pub claim_tvl: u128,
}

impl LendingDesk {
    pub fn connect_offer_fee_ceil(
        &mut self,
        borrower: u64,
        principal: u128,
        borrow_duration: u128,
        fee_per_day: u128,
    ) -> u128 {
        let fee_percentage = ceil_div(borrow_duration * fee_per_day, 86_400);
        let fee_amount = mul_div_up(principal, fee_percentage, 10_000);
        self.protocol_fees += fee_amount;
        self.receiver_payouts.push((borrower, principal - fee_amount));
        fee_amount
    }

    pub fn before_withdraw_mul_before_div(
        &mut self,
        user: u64,
        assets: u128,
    ) -> u128 {
        let entitled_amount = assets
            .checked_mul(self.claim_tvl)
            .expect("withdraw payout overflow")
            .checked_div(self.final_tvl)
            .expect("nonzero final tvl");
        self.treasury_payouts.push((user, entitled_amount));
        entitled_amount
    }
}

fn ceil_div(numerator: u128, denominator: u128) -> u128 {
    (numerator + denominator - 1) / denominator
}

fn mul_div_up(a: u128, b: u128, c: u128) -> u128 {
    ceil_div(a * b, c)
}
