use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeNavi;
#[contractimpl]
impl SafeNavi {
    // OK: both use the same oracle_price source
    pub fn calculate_max_liquidation(position_id: u64) -> (u128, u128) {
        let price = oracle_price(position_id);
        let max_liquidable_collateral = price * 100;
        let max_liquidable_debt = price * 200;
        (max_liquidable_collateral, max_liquidable_debt)
    }
}
fn oracle_price(_p: u64) -> u128 { 0 }
