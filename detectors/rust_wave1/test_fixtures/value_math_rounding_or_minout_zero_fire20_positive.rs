use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Fire20ValueMath;

#[contractimpl]
impl Fire20ValueMath {
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

    pub fn ask_exact_amount_out(amount_out: u128, reserve_in: u128, fee_bps: u128) -> u128 {
        let numerator = amount_out * 10_000;
        let denominator = reserve_in - amount_out - fee_bps;
        numerator / denominator
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
        recipient: Address,
    ) {
        let client = RouterClient::new(&env, &router);
        client.exact_input_single(&amount_in, &0, &recipient);
    }
}

pub struct RouterClient;

impl RouterClient {
    pub fn new(_env: &Env, _router: &Address) -> Self {
        RouterClient
    }

    pub fn swap_exact_in(&self, _amount_in: &i128, _path: &Address) {}

    pub fn exact_input_single(
        &self,
        _amount_in: &i128,
        _min_out: &i128,
        _recipient: &Address,
    ) {
    }
}
