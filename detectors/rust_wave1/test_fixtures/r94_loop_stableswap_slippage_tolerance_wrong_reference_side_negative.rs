use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeStableSwap;
#[contractimpl]
impl SafeStableSwap {
    // OK: compares against expected (nominal) deposit
    pub fn provide_liquidity(actual_deposit: u128, expected: u128, tolerance_bps: u128) -> bool {
        let _ = tolerance_bps;
        actual_deposit >= expected * 99 / 100
    }
}
