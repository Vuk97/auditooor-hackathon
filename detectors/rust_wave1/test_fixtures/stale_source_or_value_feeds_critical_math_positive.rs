use soroban_sdk::{contract, contractimpl, Address, Env};

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
        let payout = collateral_value.saturating_sub(debt);
        payout
    }

    pub fn settle_snapshot_payout(
        cached_collateral_value: u128,
        snapshot_debt: u128,
    ) -> u128 {
        let seize_amount = cached_collateral_value.saturating_sub(snapshot_debt);
        let burn_amount = seize_amount / 2;
        seize_amount.saturating_sub(burn_amount)
    }
}
