pub struct SafeRedeemVault {
    pub reserve_assets: u128,
    pub burned_shares: u128,
    pub protocol_fees: u128,
    pub rounding_carry: u128,
}

impl SafeRedeemVault {
    pub fn withdraw_rounds_shares_to_burn_up(
        &mut self,
        caller: [u8; 32],
        requested_assets: u128,
        total_shares: u128,
        total_assets: u128,
    ) -> Option<()> {
        let shares_to_burn = requested_assets.checked_mul(total_shares)?.div_ceil(total_assets);
        self.burn_shares(caller, shares_to_burn);
        self.transfer_assets(caller, requested_assets);
        Some(())
    }

    pub fn redeem_rejects_non_exact_asset_division(
        &mut self,
        caller: [u8; 32],
        shares: u128,
        total_assets: u128,
        total_shares: u128,
    ) -> Result<(), &'static str> {
        let scaled_assets = shares.checked_mul(total_assets).ok_or("overflow")?;
        let assets_out = scaled_assets.checked_div(total_shares).ok_or("zero denom")?;
        if scaled_assets % total_shares != 0 {
            return Err("non exact redeem");
        }
        self.transfer_assets(caller, assets_out);
        Ok(())
    }

    pub fn redeem_checks_min_out_against_net_assets(
        &mut self,
        caller: [u8; 32],
        shares: u128,
        total_assets: u128,
        total_shares: u128,
        fee_bps: u128,
        min_assets: u128,
    ) -> Result<(), &'static str> {
        let gross_assets = mul_div(shares, total_assets, total_shares)?;
        let redeem_fee = gross_assets.checked_mul(fee_bps).ok_or("overflow")?.div_ceil(10_000);
        let net_assets = gross_assets.checked_sub(redeem_fee).ok_or("fee")?;
        if net_assets < min_assets {
            return Err("too little net");
        }
        self.protocol_fees += redeem_fee;
        self.transfer_assets(caller, net_assets);
        Ok(())
    }

    pub fn preview_redeem_quote_without_writeback(
        &self,
        shares: u128,
        total_assets: u128,
        total_shares: u128,
    ) -> Option<u128> {
        let assets_out = shares.checked_mul(total_assets)?.checked_div(total_shares)?;
        Some(assets_out)
    }

    pub fn carry_fee_rounding_remainder(
        &mut self,
        gross_assets: u128,
        fee_bps: u128,
    ) -> Option<()> {
        let scaled_fee = gross_assets.checked_mul(fee_bps)?;
        let redeem_fee = scaled_fee.checked_div(10_000)?;
        let remainder = scaled_fee.checked_rem(10_000)?;
        self.rounding_carry += remainder;
        self.protocol_fees += redeem_fee;
        Some(())
    }

    fn burn_shares(&mut self, _caller: [u8; 32], shares: u128) {
        self.burned_shares += shares;
    }

    fn transfer_assets(&mut self, _caller: [u8; 32], assets: u128) {
        self.reserve_assets = self.reserve_assets.saturating_sub(assets);
    }
}

fn mul_div(value: u128, numerator: u128, denominator: u128) -> Result<u128, &'static str> {
    value
        .checked_mul(numerator)
        .ok_or("overflow")?
        .checked_div(denominator)
        .ok_or("zero denom")
}
