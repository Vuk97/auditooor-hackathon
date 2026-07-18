use soroban_sdk::{contract, contractimpl, Address, Env};

#[derive(Debug, PartialEq, Eq)]
pub enum MathError {
    EmptySupply,
    Overflow,
    Slippage,
}

#[contract]
pub struct SafeFire20ValueMath;

#[contractimpl]
impl SafeFire20ValueMath {
    pub fn redeem_checked_mul_before_div(
        _env: Env,
        shares: u128,
        total_shares: u128,
        total_assets: u128,
    ) -> Result<u128, MathError> {
        if total_shares == 0 {
            return Err(MathError::EmptySupply);
        }
        let asset_payout = shares
            .checked_mul(total_assets)
            .ok_or(MathError::Overflow)?
            .checked_div(total_shares)
            .ok_or(MathError::EmptySupply)?;
        Ok(asset_payout)
    }

    pub fn ask_exact_amount_out(amount_out: u128, reserve_in: u128, fee_bps: u128) -> u128 {
        let numerator = amount_out * 10_000;
        let denominator = reserve_in - amount_out - fee_bps;
        mul_div_up(numerator, 1, denominator)
    }

    pub fn execute_swap_with_min_out(
        env: Env,
        router: Address,
        amount_in: i128,
        user_min_out: i128,
        path: Address,
    ) -> Result<(), MathError> {
        if user_min_out <= 0 {
            return Err(MathError::Slippage);
        }
        let client = RouterClient::new(&env, &router);
        client.swap_exact_in(&amount_in, &user_min_out, &path);
        Ok(())
    }
}

fn mul_div_up(a: u128, b: u128, c: u128) -> u128 {
    (a * b + c - 1) / c
}

pub struct RouterClient;

impl RouterClient {
    pub fn new(_env: &Env, _router: &Address) -> Self {
        RouterClient
    }

    pub fn swap_exact_in(&self, _amount_in: &i128, _min_out: &i128, _path: &Address) {}
}
