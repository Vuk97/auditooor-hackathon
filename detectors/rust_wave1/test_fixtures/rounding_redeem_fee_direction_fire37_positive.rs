pub struct RedeemVault {
    pub reserve_assets: u128,
    pub burned_shares: u128,
    pub protocol_fees: u128,
}

impl RedeemVault {
    pub fn withdraw_floor_shares_to_burn(
        &mut self,
        caller: [u8; 32],
        requested_assets: u128,
        total_shares: u128,
        total_assets: u128,
    ) -> Option<()> {
        let shares_to_burn = requested_assets.checked_mul(total_shares)?.checked_div(total_assets)?;
        self.burn_shares(caller, shares_to_burn);
        self.transfer_assets(caller, requested_assets);
        Some(())
    }

    pub fn redeem_fee_after_truncated_assets(
        &mut self,
        caller: [u8; 32],
        shares: u128,
        total_assets: u128,
        total_shares: u128,
        fee_bps: u128,
    ) -> Option<()> {
        let gross_assets = shares.checked_mul(total_assets)?.checked_div(total_shares)?;
        let redeem_fee = gross_assets.checked_mul(fee_bps)?.checked_div(10_000)?;
        let net_assets = gross_assets.checked_sub(redeem_fee)?;
        self.protocol_fees += redeem_fee;
        self.transfer_assets(caller, net_assets);
        Some(())
    }

    pub fn redeem_min_out_checks_gross_before_fee(
        &mut self,
        caller: [u8; 32],
        shares: u128,
        total_assets: u128,
        total_shares: u128,
        fee_bps: u128,
        min_assets: u128,
    ) -> Result<(), &'static str> {
        let gross_assets = shares.checked_mul(total_assets).unwrap().checked_div(total_shares).unwrap();
        let redeem_fee = gross_assets.checked_mul(fee_bps).unwrap().checked_div(10_000).unwrap();
        let net_assets = gross_assets.checked_sub(redeem_fee).unwrap();
        if gross_assets < min_assets {
            return Err("too little gross");
        }
        self.transfer_assets(caller, net_assets);
        Ok(())
    }

    pub fn burn_ceil_assets_out_drains_reserves(
        &mut self,
        caller: [u8; 32],
        shares: u128,
        exchange_rate: u128,
    ) {
        let assets_out = shares.div_ceil(exchange_rate);
        self.reserve_assets -= assets_out;
        self.transfer_assets(caller, assets_out);
    }

    fn burn_shares(&mut self, _caller: [u8; 32], shares: u128) {
        self.burned_shares += shares;
    }

    fn transfer_assets(&mut self, _caller: [u8; 32], assets: u128) {
        self.reserve_assets = self.reserve_assets.saturating_sub(assets);
    }
}
