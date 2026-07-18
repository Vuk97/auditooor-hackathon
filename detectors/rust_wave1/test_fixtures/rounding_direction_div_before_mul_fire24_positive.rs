use std::collections::HashMap;

pub struct FeeVault {
    pub protocol_fees: u128,
    pub user_balances: HashMap<u64, u128>,
}

impl FeeVault {
    pub fn settle_fee_rounds_user_favorable(
        &mut self,
        user: u64,
        amount: u128,
        fee_bps: u128,
    ) -> u128 {
        let protocol_fee = amount / 10_000 * fee_bps;
        let user_amount = amount - protocol_fee;

        self.protocol_fees += protocol_fee;
        self.user_balances.insert(user, user_amount);
        user_amount
    }
}

pub struct RewardVault {
    pub rewards: HashMap<u64, u128>,
    pub reward_debt: u128,
}

impl RewardVault {
    pub fn claim_reward_floor_first(
        &mut self,
        user: u64,
        user_shares: u128,
        total_shares: u128,
        epoch_reward: u128,
    ) -> u128 {
        let reward_fraction = user_shares / total_shares;
        let reward_payout = reward_fraction * epoch_reward;

        self.reward_debt += reward_payout;
        self.rewards.insert(user, reward_payout);
        reward_payout
    }
}

pub struct LiquidationBook {
    pub debt_shares: u128,
    pub collateral_out: HashMap<u64, u128>,
}

impl LiquidationBook {
    pub fn liquidate_with_floor_before_bonus(
        &mut self,
        liquidator: u64,
        repay_amount: u128,
        total_debt: u128,
        total_debt_shares: u128,
        collateral_pool: u128,
    ) -> u128 {
        let shares_repaid = repay_amount
            .checked_div(total_debt)
            .expect("nonzero debt")
            .checked_mul(total_debt_shares)
            .expect("share math overflow");
        let bonus_collateral = shares_repaid * collateral_pool / total_debt_shares;

        self.debt_shares -= shares_repaid;
        self.collateral_out.insert(liquidator, bonus_collateral);
        bonus_collateral
    }
}
