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
        let burn_amount = current_payout / 2;
        current_payout.saturating_sub(burn_amount)
    }
}
