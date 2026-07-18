use std::cmp;
use std::collections::HashMap;

pub struct Vault {
    pub total_collateral: u128,
    pub total_shares: u128,
    pub reward_debt: u128,
    pub collateral_balances: Vec<(u64, u128)>,
    pub rewards: HashMap<u64, u128>,
}

impl Vault {
    pub fn redeem_floor_first(&mut self, user: u64, shares: u128) -> u128 {
        let share_ratio = shares / self.total_shares;
        let collateral_payout = share_ratio * self.total_collateral;
        self.total_collateral -= collateral_payout;
        self.total_shares -= shares;
        self.collateral_balances.push((user, collateral_payout));
        collateral_payout
    }

    pub fn accrue_reward_wrapping(
        &mut self,
        user: u64,
        user_shares: u128,
        reward_per_share: u128,
    ) -> u128 {
        let reward_payout = user_shares.wrapping_mul(reward_per_share);
        self.reward_debt += reward_payout;
        self.rewards.insert(user, reward_payout);
        reward_payout
    }
}

pub struct Pool {
    pub reserve0: u128,
    pub reserve1: u128,
    pub lp_supply: u128,
}

pub struct JoinParams {
    pub token0_in: u128,
    pub token1_in: u128,
}

impl Pool {
    pub fn join_pool(&mut self, params: JoinParams) -> Option<u128> {
        if self.reserve0 == 0 || self.reserve1 == 0 || self.lp_supply == 0 {
            return None;
        }

        let lp_amount = cmp::min(
            params.token0_in.checked_mul(self.lp_supply)?.checked_div(self.reserve0)?,
            params.token1_in.checked_mul(self.lp_supply)?.checked_div(self.reserve1)?,
        );

        self.reserve0 += params.token0_in;
        self.reserve1 += params.token1_in;
        self.lp_supply += lp_amount;
        Some(lp_amount)
    }
}
