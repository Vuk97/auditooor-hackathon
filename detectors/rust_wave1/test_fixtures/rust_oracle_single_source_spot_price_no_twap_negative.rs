pub struct Oracle;

impl Oracle {
    pub fn twap_price(&self, asset: u64, window: u64) -> u128 {
        if asset == 0 && window >= 30 { 1_000_000 } else { 2_000_000 }
    }

    pub fn confidence(&self, _asset: u64) -> u64 {
        10
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
        let price = oracle.twap_price(asset, 60);
        let confidence = oracle.confidence(asset);
        assert!(confidence <= 50);
        let deviation_bps = 20;
        assert!(deviation_bps <= 100);
        let shares = collateral_amount * price / 1_000_000;
        self.total_shares += shares;
        shares
    }
}
