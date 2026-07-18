use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SafeValueMath;

#[derive(Debug)]
pub enum Error {
    Overflow,
    Slippage,
}

#[contractimpl]
impl SafeValueMath {
    pub fn redeem_multiply_first(
        _env: Env,
        shares: u128,
        total_shares: u128,
        total_assets: u128,
    ) -> Result<u128, Error> {
        let asset_payout = shares
            .checked_mul(total_assets)
            .ok_or(Error::Overflow)?
            .checked_div(total_shares)
            .ok_or(Error::Overflow)?;
        Ok(asset_payout)
    }

    pub fn accrue_reward_checked(
        _env: Env,
        user_shares: u128,
        reward_per_share: u128,
    ) -> Result<u128, Error> {
        let reward_payout = user_shares
            .checked_mul(reward_per_share)
            .ok_or(Error::Overflow)?;
        Ok(reward_payout)
    }

    pub fn execute_swap_with_min_out(
        env: Env,
        router: Address,
        amount_in: i128,
        min_out: i128,
        path: Address,
    ) -> Result<(), Error> {
        if min_out <= 0 {
            return Err(Error::Slippage);
        }

        let client = RouterClient::new(&env, &router);
        client.exact_input(&amount_in, &min_out, &path);
        Ok(())
    }
}

pub struct RouterClient;

impl RouterClient {
    pub fn new(_env: &Env, _router: &Address) -> Self {
        RouterClient
    }

    pub fn exact_input(&self, _amount_in: &i128, _min_out: &i128, _path: &Address) {}
}
