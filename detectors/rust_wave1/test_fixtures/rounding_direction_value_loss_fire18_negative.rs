use std::cmp;
use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq)]
pub enum MathError {
    Overflow,
    Underflow,
    EmptySupply,
    Slippage,
}

pub struct Vault {
    pub total_collateral: u128,
    pub total_shares: u128,
    pub reward_debt: u128,
    pub collateral_balances: Vec<(u64, u128)>,
    pub rewards: HashMap<u64, u128>,
}

impl Vault {
    pub fn redeem_mul_before_div_checked(
        &mut self,
        user: u64,
        shares: u128,
    ) -> Result<u128, MathError> {
        if self.total_shares == 0 {
            return Err(MathError::EmptySupply);
        }
        let collateral_payout = shares
            .checked_mul(self.total_collateral)
            .ok_or(MathError::Overflow)?
            .checked_div(self.total_shares)
            .ok_or(MathError::EmptySupply)?;

        self.total_collateral = self
            .total_collateral
            .checked_sub(collateral_payout)
            .ok_or(MathError::Underflow)?;
        self.total_shares = self
            .total_shares
            .checked_sub(shares)
            .ok_or(MathError::Underflow)?;
        self.collateral_balances.push((user, collateral_payout));
        Ok(collateral_payout)
    }

    pub fn accrue_reward_checked(
        &mut self,
        user: u64,
        user_shares: u128,
        reward_per_share: u128,
    ) -> Result<u128, MathError> {
        let reward_payout = user_shares
            .checked_mul(reward_per_share)
            .ok_or(MathError::Overflow)?;
        self.reward_debt = self
            .reward_debt
            .checked_add(reward_payout)
            .ok_or(MathError::Overflow)?;
        self.rewards.insert(user, reward_payout);
        Ok(reward_payout)
    }
}

pub struct Pool {
    pub reserve0: u128,
    pub reserve1: u128,
    pub lp_supply: u128,
}

pub struct JoinParams {
    pub max_token0_in: u128,
    pub max_token1_in: u128,
    pub min_lp_out: u128,
}

impl Pool {
    pub fn join_pool_checked(&mut self, params: JoinParams) -> Result<u128, MathError> {
        if self.reserve0 == 0 || self.reserve1 == 0 || self.lp_supply == 0 {
            return Err(MathError::EmptySupply);
        }

        let lp_from_0 = params
            .max_token0_in
            .checked_mul(self.lp_supply)
            .ok_or(MathError::Overflow)?
            .checked_div(self.reserve0)
            .ok_or(MathError::EmptySupply)?;
        let lp_from_1 = params
            .max_token1_in
            .checked_mul(self.lp_supply)
            .ok_or(MathError::Overflow)?
            .checked_div(self.reserve1)
            .ok_or(MathError::EmptySupply)?;
        let lp_amount = cmp::min(lp_from_0, lp_from_1);

        if lp_amount < params.min_lp_out {
            return Err(MathError::Slippage);
        }
        let token0_used = lp_amount
            .checked_mul(self.reserve0)
            .ok_or(MathError::Overflow)?
            .checked_div(self.lp_supply)
            .ok_or(MathError::EmptySupply)?;
        let token1_used = lp_amount
            .checked_mul(self.reserve1)
            .ok_or(MathError::Overflow)?
            .checked_div(self.lp_supply)
            .ok_or(MathError::EmptySupply)?;
        if token0_used > params.max_token0_in || token1_used > params.max_token1_in {
            return Err(MathError::Slippage);
        }

        self.reserve0 = self
            .reserve0
            .checked_add(token0_used)
            .ok_or(MathError::Overflow)?;
        self.reserve1 = self
            .reserve1
            .checked_add(token1_used)
            .ok_or(MathError::Overflow)?;
        self.lp_supply = self
            .lp_supply
            .checked_add(lp_amount)
            .ok_or(MathError::Overflow)?;
        Ok(lp_amount)
    }
}
