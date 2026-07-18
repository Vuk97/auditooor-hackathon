use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct CurvePool { addr: Address }
impl CurvePool {
    fn get_virtual_price(&self) -> u128 { 1_000_000_000_000_000_000 }
}
#[contract]
pub struct StableCurveOracle;
#[contractimpl]
impl StableCurveOracle {
    // BUG: reads get_virtual_price() with no read-only-reentrancy guard
    pub fn get_price(pool: CurvePool) -> u128 {
        pool.get_virtual_price()
    }
}
