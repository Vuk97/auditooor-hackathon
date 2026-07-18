use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct StableSwap;
#[contractimpl]
impl StableSwap {
    // BUG: slippage tolerance compares actual_deposit against pool's total balance
    pub fn provide_liquidity(actual_deposit: u128, pool_balance: u128, tolerance_bps: u128) -> bool {
        let _ = tolerance_bps;
        let total_pool = pool_balance;
        actual_deposit >= total_pool * 99 / 100
    }
}
