use std::collections::HashMap;

fn mul_div_floor_checked(a: u128, b: u128, c: u128) -> Result<u128, &'static str> {
    a.checked_mul(b)
        .ok_or("mul overflow")?
        .checked_div(c)
        .ok_or("zero denominator")
}

fn ceil_div(a: u128, b: u128) -> Result<u128, &'static str> {
    let adjusted = a
        .checked_add(b.checked_sub(1).ok_or("zero denominator")?)
        .ok_or("ceil overflow")?;
    adjusted.checked_div(b).ok_or("zero denominator")
}

pub struct FeeVault {
    pub protocol_fees: u128,
    pub user_balances: HashMap<u64, u128>,
}

impl FeeVault {
    pub fn settle_fee_protocol_favorable(
        &mut self,
        user: u64,
        amount: u128,
        fee_bps: u128,
    ) -> Result<u128, &'static str> {
        let raw_fee = amount.checked_mul(fee_bps).ok_or("fee overflow")?;
        let protocol_fee = ceil_div(raw_fee, 10_000)?;
        if protocol_fee == 0 {
            return Err("zero protocol fee rejected");
        }
        let user_amount = amount.checked_sub(protocol_fee).ok_or("fee exceeds amount")?;

        self.protocol_fees = self
            .protocol_fees
            .checked_add(protocol_fee)
            .ok_or("fee accumulator overflow")?;
        self.user_balances.insert(user, user_amount);
        Ok(user_amount)
    }
}

pub struct RewardVault {
    pub rewards: HashMap<u64, u128>,
    pub reward_debt: u128,
}

impl RewardVault {
    pub fn claim_reward_mul_before_div(
        &mut self,
        user: u64,
        user_shares: u128,
        total_shares: u128,
        epoch_reward: u128,
    ) -> Result<u128, &'static str> {
        let reward_payout = mul_div_floor_checked(user_shares, epoch_reward, total_shares)?;

        self.reward_debt = self
            .reward_debt
            .checked_add(reward_payout)
            .ok_or("reward debt overflow")?;
        self.rewards.insert(user, reward_payout);
        Ok(reward_payout)
    }
}

pub struct LiquidationBook {
    pub debt_shares: u128,
    pub collateral_out: HashMap<u64, u128>,
}

impl LiquidationBook {
    pub fn liquidate_with_checked_share_math(
        &mut self,
        liquidator: u64,
        repay_amount: u128,
        total_debt: u128,
        total_debt_shares: u128,
        collateral_pool: u128,
    ) -> Result<u128, &'static str> {
        let shares_repaid = mul_div_floor_checked(repay_amount, total_debt_shares, total_debt)?;
        if shares_repaid == 0 {
            return Err("zero debt share repayment rejected");
        }
        let bonus_collateral =
            mul_div_floor_checked(shares_repaid, collateral_pool, total_debt_shares)?;

        self.debt_shares = self
            .debt_shares
            .checked_sub(shares_repaid)
            .ok_or("debt share underflow")?;
        self.collateral_out.insert(liquidator, bonus_collateral);
        Ok(bonus_collateral)
    }
}
