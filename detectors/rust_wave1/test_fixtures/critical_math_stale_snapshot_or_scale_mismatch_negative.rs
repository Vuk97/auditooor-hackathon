use soroban_sdk::{contract, contractimpl, Address, Env};

pub struct Reflector;
impl Reflector {
    pub fn new(_env: &Env, _addr: &Address) -> Self { Reflector }
    pub fn lastprice(&self, _asset: &Address) -> Option<u128> { Some(250) }
}

fn validate_price_staleness(_env: &Env, _price: u128) -> Result<(), ()> { Ok(()) }
fn refresh_collateral_value(collateral_amount: u128, price: u128) -> u128 {
    collateral_amount * price / 100
}
fn accrue_debt(debt: u128) -> u128 {
    debt.saturating_add(5)
}
fn normalize_assets_to_shares(
    asset_amount: u128,
    total_shares: u128,
    asset_decimals: u32,
    share_decimals: u32,
) -> u128 {
    let decimals_diff = asset_decimals.abs_diff(share_decimals);
    let scale = 10u128.pow(decimals_diff);
    asset_amount * total_shares / scale
}

#[contract]
pub struct GoodMath;

#[contractimpl]
impl GoodMath {
    pub fn liquidate_position(
        env: Env,
        addr: Address,
        asset: Address,
        collateral_amount: u128,
        debt: u128,
    ) -> u128 {
        let r = Reflector::new(&env, &addr);
        let price = r.lastprice(&asset).unwrap_or(0);
        validate_price_staleness(&env, price).ok();
        let current_collateral_value = refresh_collateral_value(collateral_amount, price);
        let current_debt = accrue_debt(debt);
        current_collateral_value.saturating_sub(current_debt)
    }

    pub fn settle_snapshot_payout(
        current_collateral_value: u128,
        current_debt: u128,
    ) -> u128 {
        let current_payout = current_collateral_value.saturating_sub(current_debt);
        current_payout / 2
    }

    pub fn convert_assets_to_shares(
        asset_amount: u128,
        total_shares: u128,
        asset_decimals: u32,
        share_decimals: u32,
    ) -> u128 {
        normalize_assets_to_shares(
            asset_amount,
            total_shares,
            asset_decimals,
            share_decimals,
        )
    }
}
