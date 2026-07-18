use std::collections::HashMap;

pub const WAD: u128 = 1_000_000_000_000_000_000;
pub const AMP_PRECISION: u128 = 1_000_000;

pub struct WithdrawalQueue {
    pub total_assets: u128,
    pub total_shares: u128,
    pub pending_payouts: HashMap<u64, u128>,
}

impl WithdrawalQueue {
    pub fn preview_redeem_divides_assets_before_user_shares(
        &mut self,
        user: u64,
        user_shares: u128,
    ) -> u128 {
        let asset_payout = self.total_assets / self.total_shares * user_shares;

        self.pending_payouts.insert(user, asset_payout);
        asset_payout
    }

    pub fn claim_withdrawable_per_share_floor_first(
        &mut self,
        user: u64,
        user_shares: u128,
    ) -> u128 {
        let withdrawable_per_share = self.total_assets / self.total_shares;
        let withdrawable_amount = user_shares * withdrawable_per_share;

        self.total_assets -= withdrawable_amount;
        self.pending_payouts.insert(user, withdrawable_amount);
        withdrawable_amount
    }
}

pub struct RewardVault {
    pub reward_debt: u128,
    pub rewards: HashMap<u64, u128>,
}

impl RewardVault {
    pub fn accrue_reward_checked_div_then_rate(
        &mut self,
        user: u64,
        accrued_rewards: u128,
        elapsed: u128,
        reward_period: u128,
        reward_rate: u128,
    ) -> Result<u128, &'static str> {
        let reward_payout = accrued_rewards
            .checked_div(reward_period)
            .ok_or("bad period")?
            .checked_mul(elapsed * reward_rate)
            .ok_or("overflow")?;

        self.reward_debt += reward_payout;
        self.rewards.insert(user, reward_payout);
        Ok(reward_payout)
    }
}

pub struct StableSwapPool {
    pub reserve_x: u128,
    pub reserve_y: u128,
    pub invariant_accumulator: u128,
}

impl StableSwapPool {
    pub fn calculate_stableswap_y_scales_after_truncation(
        &mut self,
        dx: u128,
    ) -> u128 {
        let scaled_dx = dx / self.reserve_x * AMP_PRECISION;
        let y_out = scaled_dx * self.reserve_y / WAD;

        self.invariant_accumulator += y_out;
        y_out
    }
}
