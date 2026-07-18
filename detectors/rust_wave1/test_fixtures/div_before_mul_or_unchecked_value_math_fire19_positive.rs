use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct ValueMath;

#[contractimpl]
impl ValueMath {
    pub fn redeem_floor_first(
        _env: Env,
        shares: u128,
        total_shares: u128,
        total_assets: u128,
    ) -> u128 {
        let share_ratio = shares / total_shares;
        let asset_payout = share_ratio * total_assets;
        asset_payout
    }

    pub fn accrue_reward_wrapping(
        _env: Env,
        user_shares: u128,
        reward_per_share: u128,
    ) -> u128 {
        let reward_payout = user_shares.wrapping_mul(reward_per_share);
        reward_payout
    }

    pub fn execute_swap_no_min_out(
        env: Env,
        router: Address,
        amount_in: i128,
        path: Address,
    ) {
        let client = RouterClient::new(&env, &router);
        client.swap_exact_in(&amount_in, &path);
    }

    pub fn execute_swap_zero_min_out(
        env: Env,
        router: Address,
        amount_in: i128,
        path: Address,
    ) {
        let client = RouterClient::new(&env, &router);
        client.exact_input(&amount_in, &0, &path);
    }
}

pub struct RouterClient;

impl RouterClient {
    pub fn new(_env: &Env, _router: &Address) -> Self {
        RouterClient
    }

    pub fn swap_exact_in(&self, _amount_in: &i128, _path: &Address) {}

    pub fn exact_input(&self, _amount_in: &i128, _min_out: &i128, _path: &Address) {}
}
