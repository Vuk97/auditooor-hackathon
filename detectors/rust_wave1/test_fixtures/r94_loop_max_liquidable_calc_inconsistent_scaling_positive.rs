use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Navi;
#[contractimpl]
impl Navi {
    // BUG: uses different sources for max_liquidable_collateral vs max_liquidable_debt
    pub fn calculate_max_liquidation(position_id: u64) -> (u128, u128) {
        let max_liquidable_collateral = oracle_price(position_id) * 100;
        let max_liquidable_debt = collateral_value(position_id) / 2;
        (max_liquidable_collateral, max_liquidable_debt)
    }
}
fn oracle_price(_p: u64) -> u128 { 0 }
fn collateral_value(_p: u64) -> u128 { 0 }
