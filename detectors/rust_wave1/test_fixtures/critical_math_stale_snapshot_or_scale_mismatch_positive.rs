use soroban_sdk::{contract, contractimpl, Address, Env};
use std::collections::HashMap;

pub struct Reflector;
impl Reflector {
    pub fn new(_env: &Env, _addr: &Address) -> Self { Reflector }
    pub fn lastprice(&self, _asset: &Address) -> Option<u128> { Some(250) }
}

#[contract]
pub struct BadMath;

#[contractimpl]
impl BadMath {
    pub fn liquidate_position(
        env: Env,
        addr: Address,
        asset: Address,
        collateral_amount: u128,
        debt: u128,
    ) -> u128 {
        let r = Reflector::new(&env, &addr);
        let price = r.lastprice(&asset).unwrap_or(0);
        let collateral_value = collateral_amount * price / 100;
        collateral_value.saturating_sub(debt)
    }

    pub fn settle_snapshot_payout(
        cached_collateral_value: u128,
        snapshot_debt: u128,
    ) -> u128 {
        let seize_amount = cached_collateral_value.saturating_sub(snapshot_debt);
        seize_amount / 2
    }

    pub fn convert_assets_to_shares(
        asset_amount: u128,
        total_shares: u128,
        strategy_decimals: u32,
        vault_decimals: u32,
    ) -> u128 {
        let _ = strategy_decimals;
        let _ = vault_decimals;
        asset_amount * total_shares / 1_000_000
    }
}

pub struct ConvictionScore {
    is_governance: HashMap<u64, bool>,
    scores: HashMap<u64, u64>,
    total_conviction: u64,
}

impl ConvictionScore {
    pub fn update_conviction_score(&mut self, user: u64, current_block: u64) {
        self.is_governance.insert(user, false);
        let prior_score = self.get_prior_conviction_score(
            user,
            current_block.saturating_sub(1),
        );
        let delta = prior_score;
        self.total_conviction = self.total_conviction.saturating_sub(delta);
        self.scores.insert(user, 0);
    }

    pub fn get_prior_conviction_score(&self, user: u64, _block: u64) -> u64 {
        *self.scores.get(&user).unwrap_or(&0)
    }
}
