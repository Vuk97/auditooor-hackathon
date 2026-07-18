pub struct Oracle;

impl Oracle {
    pub fn latest_price(&self, asset: u64) -> u128 {
        if asset == 0 { 1_000_000 } else { 2_000_000 }
    }
}

pub struct Vault {
    pub total_shares: u128,
}

impl Vault {
    pub fn mint_against_collateral(
        &mut self,
        oracle: &Oracle,
        asset: u64,
        collateral_amount: u128,
    ) -> u128 {
        let spot_price = oracle.latest_price(asset);
        let shares = collateral_amount * spot_price / 1_000_000;
        self.total_shares += shares;
        shares
    }
}
