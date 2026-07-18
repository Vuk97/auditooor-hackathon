use std::collections::HashMap;

pub struct U256(u128);

impl U256 {
    pub fn from(value: u128) -> Self {
        Self(value)
    }

    pub fn as_u128(self) -> u128 {
        self.0
    }
}

impl core::ops::Mul for U256 {
    type Output = U256;

    fn mul(self, rhs: U256) -> U256 {
        U256(self.0 * rhs.0)
    }
}

impl core::ops::Div for U256 {
    type Output = U256;

    fn div(self, rhs: U256) -> U256 {
        U256(self.0 / rhs.0)
    }
}

pub fn mul_div_floor(value: u128, numerator: u128, denominator: u128) -> u128 {
    value * numerator / denominator
}

pub fn checked_multiply_ratio(value: u128, numerator: u128, denominator: u128) -> u128 {
    value * numerator / denominator
}

pub struct SafeWithdrawalQueue {
    pub total_assets: u128,
    pub total_shares: u128,
    pub pending_payouts: HashMap<u64, u128>,
}

impl SafeWithdrawalQueue {
    pub fn preview_redeem_uses_mul_div_helper(
        &mut self,
        user: u64,
        user_shares: u128,
    ) -> u128 {
        let asset_payout = mul_div_floor(user_shares, self.total_assets, self.total_shares);

        self.pending_payouts.insert(user, asset_payout);
        asset_payout
    }

    pub fn preview_redeem_checked_mul_before_divide(
        &mut self,
        user: u64,
        user_shares: u128,
    ) -> Result<u128, &'static str> {
        let asset_payout = user_shares
            .checked_mul(self.total_assets)
            .ok_or("overflow")?
            .checked_div(self.total_shares)
            .ok_or("bad supply")?;

        self.pending_payouts.insert(user, asset_payout);
        Ok(asset_payout)
    }

    pub fn preview_redeem_widened_u256_intermediate(
        &mut self,
        user: u64,
        user_shares: u128,
    ) -> u128 {
        let numerator = U256::from(user_shares) * U256::from(self.total_assets);
        let asset_payout = (numerator / U256::from(self.total_shares)).as_u128();

        self.pending_payouts.insert(user, asset_payout);
        asset_payout
    }

    pub fn preview_redeem_ratio_helper(
        &mut self,
        user: u64,
        user_shares: u128,
    ) -> u128 {
        let asset_payout = checked_multiply_ratio(
            user_shares,
            self.total_assets,
            self.total_shares,
        );

        self.pending_payouts.insert(user, asset_payout);
        asset_payout
    }

    pub fn normalize_pixels_generic_math(width: u128, height: u128, scale: u128) -> u128 {
        let normalized = width / height * scale;
        normalized
    }
}
